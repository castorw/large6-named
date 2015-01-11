import SocketServer
import threading
import dnslib
import ipaddress
import json
import logging
import time

__author__ = 'Lubomir Kaplan <castor@castor.sk>'

named_logger = None
prefix_logger = None
handler_logger = None
name_server = None


class NameServerException(Exception):
    pass


class PrefixException(NameServerException):
    pass


class AddressNotCoveredException(PrefixException):
    pass


class HandlingException(NameServerException):
    pass


class RecordNotFoundException(HandlingException):
    pass


class UdpDnsRequestHandler(SocketServer.BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

    def handle(self):
        global handler_logger, name_server
        try:
            request_raw = self.get_data()
            request = dnslib.DNSRecord.parse(request_raw)
            reply = dnslib.DNSRecord(dnslib.DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            request_name = request.q.qname
            request_type = request.q.qtype
            request_name_uc = unicode(request_name)
            if request_name_uc.endswith(".ip6.arpa."):
                handler_logger.debug("%s requested reverse ipv6 %s: %s" % (self.client_address[0],
                                                                           dnslib.QTYPE[request_type],
                                                                           request_name_uc))
                ipv6_uc = request_name_uc[:-9].replace(".", "")[::-1]
                ipv6_uc = ':'.join(ipv6_uc[i:i+4] for i in range(0, len(ipv6_uc), 4))
                ipv6_address = ipaddress.ip_address(ipv6_uc)
                ns_result = None
                for prefix in name_server.prefixes:
                    try:
                        if prefix.config["Version"] == 6:
                            ns_result = prefix.reverse_resolve(request_name, ipv6_address, request_type)
                    except PrefixException:
                        continue
                    except AddressNotCoveredException:
                        continue
                if ns_result is None:
                    raise RecordNotFoundException("no record found for %s" % request_name_uc)
                reply.header.set_rcode(dnslib.RCODE.NOERROR)
                for rr in ns_result:
                    reply.add_answer(rr)
                handler_logger.info("%s got response with %d records for ipv6 %s request: %s" % (
                    self.client_address[0], len(ns_result), dnslib.QTYPE[request_type], request_name_uc))
            else:
                raise HandlingException("unsupported query for %s" % request_name_uc)
        except RecordNotFoundException as e:
            handler_logger.info("%s %s" % (self.client_address[0], e.message))
            reply.header.set_rcode(dnslib.RCODE.NXDOMAIN)
        except HandlingException as e:
            handler_logger.info("%s %s" % (self.client_address[0], e.message))
            reply.header.set_rcode(dnslib.RCODE.SERVFAIL)

        self.send_data(reply.pack())
        pass


class Prefix():
    def __init__(self, prefix, config):
        global prefix_logger
        """:type : logging.Logger"""
        self.logger = prefix_logger
        self.logger.debug("loading prefix %s" % prefix)
        self.raw_prefix = prefix
        self.config = config

        if self.config["Version"] != 6:
            raise PrefixException("only ipv6 prefixes are currently supported")
        self.ip_network = ipaddress.ip_network(prefix)

        if self.config["ReverseZone"]:
            zn_rev = self.ip_network.network_address.exploded.replace(":", "")[:self.ip_network.prefixlen/4][::-1]
            zn = ".".join(zn_rev[::]) + ".ip6.arpa."
            self.reverse_zone_name = zn
            self.logger.debug("%s will get reverse zone %s" % (self.ip_network, self.reverse_zone_name))
            soa_config = self.config["StartOfAuthority"]
            self.soa_record = dnslib.SOA(
                mname=soa_config["PrimaryNameServer"],
                rname=soa_config["AdminContact"],
                times=(
                    soa_config["SerialNumber"],
                    soa_config["RefreshTime"],
                    soa_config["RetryTime"],
                    soa_config["ExpireTime"],
                    soa_config["MinimumTTL"]
                )
            )
            self.logger.debug("reverse zone %s soa record: %s" % (self.reverse_zone_name, self.soa_record))
            self.ns_records = list()
            for ns in self.config["NameServers"]:
                self.ns_records.append(dnslib.NS(ns))
            self.logger.debug("reverse zone %s ns records: %s" % (self.reverse_zone_name,
                                                                  ", ".join(self.config["NameServers"])))
            self.logger.info("reverse zone %s for prefix %s: loaded serial %d" % (self.reverse_zone_name,
                                                                                  self.ip_network,
                                                                                  self.soa_record.times[0]))

        if self.config["ForwardZone"]:
            self.logger.warn("forward zone for prefix %s will not be created: not implemented yet" % self.ip_network)

        pass

    def reverse_resolve(self, request_name, ip_address, type):
        if not self.config["ReverseZone"]:
            raise PrefixException("prefix %s does not provide reverse zone" % self.ip_network)
        if not ip_address in self.ip_network:
            raise AddressNotCoveredException("address %s is not within prefix %s" % (ip_address, self.ip_network))
        records = list()
        if type == dnslib.QTYPE.SOA:
            records.append(dnslib.RR(rname=self.reverse_zone_name, rtype=dnslib.QTYPE.SOA,
                                     rclass=1, ttl=self.config["RecordTTL"],
                                     rdata=self.soa_record))
            for ns_record in self.ns_records:
                records.append(dnslib.RR(rname=self.reverse_zone_name, rtype=dnslib.QTYPE.NS,
                                         rclass=1, ttl=self.config["RecordTTL"],
                                         rdata=ns_record))
            return records
        elif type == dnslib.QTYPE.PTR:
            remain_name = ip_address.exploded.replace(":", "")[self.ip_network.prefixlen/4:]
            full_name = ip_address.exploded.replace(":", "")
            ptr_data = self.config["RecordPattern"]
            ptr_data = ptr_data.replace("%r", remain_name)
            ptr_data = ptr_data.replace("%f", full_name)
            self.logger.debug("%s resolved to %s" % (ip_address, ptr_data))
            records = list()
            records.append(dnslib.RR(rname=request_name, rtype=dnslib.QTYPE.PTR,
                                     rclass=1, ttl=self.config["RecordTTL"],
                                     rdata=dnslib.PTR(ptr_data)))
            return records
        else:
            raise PrefixException("unsupported record type %s" % dnslib.QTYPE[type])


class NameServer():

    def __init__(self):
        # load configuration
        self.config_file = open("large6-named.conf", "r")
        self.config = json.loads(self.config_file.read())

        # initialize logging
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        lfh = logging.FileHandler(filename="large6-named.log")
        lfh.setFormatter(formatter)
        cfh = logging.StreamHandler()
        cfh.setFormatter(formatter)

        global named_logger, prefix_logger, handler_logger
        named_logger = logging.Logger("named")
        named_logger.setLevel(logging.DEBUG)
        named_logger.addHandler(lfh)
        named_logger.addHandler(cfh)
        self.logger = named_logger

        prefix_logger = logging.Logger("prefix")
        prefix_logger.setLevel(logging.DEBUG)
        prefix_logger.addHandler(lfh)
        prefix_logger.addHandler(cfh)

        handler_logger = logging.Logger("handler")
        handler_logger.setLevel(logging.DEBUG)
        handler_logger.addHandler(lfh)
        handler_logger.addHandler(cfh)

        self.logger.info("logging initialized")

        global name_server
        name_server = self

        self.udp_server = SocketServer.ThreadingUDPServer((self.config["Configuration"]["ServerAddress"],
                                                           self.config["Configuration"]["ServerPort"]),
                                                          UdpDnsRequestHandler)

        self.logger.debug("loading configuration")

        self.prefixes = list()
        for prefix, prefix_config in self.config["Prefixes"].items():
            self.prefixes.append(Prefix(prefix, prefix_config))

        pass

    def start(self):
        thread = threading.Thread(target=self.udp_server.serve_forever)
        thread.daemon = True
        thread.start()
        self.logger.info("server has successfully started on %s at udp/%d" %
                         (self.config["Configuration"]["ServerAddress"], self.config["Configuration"]["ServerPort"]))
        try:
            while 1:
                time.sleep(1)

        except KeyboardInterrupt:
            pass
        finally:
            self.udp_server.shutdown()
            pass


def main():
    server = NameServer()
    server.start()

if __name__ == '__main__':
    main()