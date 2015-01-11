import SocketServer
import threading
import dnslib
import ipaddress
import json
import logging
import time
import re

__author__ = 'Lubomir Kaplan <castor@castor.sk>'

named_logger = None
prefix_logger = None
handler_logger = None
name_server = None


class NameServerException(Exception):
    pass


class PrefixException(NameServerException):
    pass


class RecordNotCoveredException(PrefixException):
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
        request_raw = self.get_data()
        request = dnslib.DNSRecord.parse(request_raw)
        reply = dnslib.DNSRecord(dnslib.DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        try:
            request_name = request.q.qname
            request_type = request.q.qtype
            request_name_uc = unicode(request_name)
            if request_name_uc.endswith(".ip6.arpa.") and (request_type in (dnslib.QTYPE.SOA, dnslib.QTYPE.PTR)):
                handler_logger.debug("%s requested reverse ipv6 %s: %s" % (self.client_address[0],
                                                                           dnslib.QTYPE[request_type],
                                                                           request_name_uc))
                ipv6_uc = request_name_uc[:-9].replace(".", "")[::-1]
                ipv6_uc = ':'.join(ipv6_uc[i:i + 4] for i in range(0, len(ipv6_uc), 4))
                ipv6_address = ipaddress.ip_address(ipv6_uc)
                ns_result = None
                for prefix in name_server.prefixes:
                    try:
                        if prefix.config["Version"] == 6:
                            ns_result = prefix.reverse_resolve(request_name, ipv6_address, request_type)
                    except PrefixException:
                        continue
                if ns_result is None:
                    raise RecordNotFoundException("no record found for %s" % request_name_uc)
                reply.header.set_rcode(dnslib.RCODE.NOERROR)
                for rr in ns_result:
                    reply.add_answer(rr)
                handler_logger.info("%s got response with %d records for ipv6 %s request: %s" % (
                    self.client_address[0], len(ns_result), dnslib.QTYPE[request_type], request_name_uc))
            else:
                handler_logger.debug("%s requested forward resolution of %s: %s" % (self.client_address[0],
                                                                                    dnslib.QTYPE[request_type],
                                                                                    request_name_uc))
                ns_result = None
                for prefix in name_server.prefixes:
                    try:
                        if prefix.config["Version"] == 6:
                            ns_result = prefix.forward_resolve(request_name, request_type)
                    except PrefixException:
                        continue
                if ns_result is None:
                    raise RecordNotFoundException("no record found for %s" % request_name_uc)
                reply.header.set_rcode(dnslib.RCODE.NOERROR)
                for rr in ns_result:
                    reply.add_answer(rr)
                handler_logger.info("%s got response with %d records for %s request: %s" % (
                    self.client_address[0], len(ns_result), dnslib.QTYPE[request_type], request_name_uc))
        except RecordNotFoundException as e:
            handler_logger.info("%s %s" % (self.client_address[0], e))
            reply.header.set_rcode(dnslib.RCODE.NXDOMAIN)
        except HandlingException as e:
            handler_logger.info("%s %s" % (self.client_address[0], e))
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
        try:
            self.ip_network = ipaddress.ip_network(prefix)
        except ValueError as ent:
            raise PrefixException("invalid prefix %s: %s" % (prefix, ent))

        if self.config["ReverseZoneEnabled"]:
            zn_rev = self.ip_network.network_address.exploded.replace(":", "")[:self.ip_network.prefixlen / 4][::-1]
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

        if self.config["ForwardZoneEnabled"]:
            if not self.config["RecordPattern"].endswith(self.config["ForwardZoneName"]):
                raise PrefixException("record pattern %s for prefix %s does not end with its forward zone name %s" % (
                    self.config["RecordPattern"], self.ip_network, self.config["ForwardZoneName"]))

            hml4 = (self.ip_network.max_prefixlen - self.ip_network.prefixlen) / 4
            mpl4 = self.ip_network.max_prefixlen / 4
            forward_zone_re_base = self.config["RecordPattern"]
            forward_zone_re_base = forward_zone_re_base.replace("%r",
                                                                "([0-9a-fA-F]{" + str(hml4) + "," + str(hml4) + "})")
            forward_zone_re_base = forward_zone_re_base.replace("%f",
                                                                "([0-9a-fA-F]{" + str(mpl4) + "," + str(mpl4) + "})")
            forward_zone_re_base = "^" + forward_zone_re_base.replace(".", "\\.") + "\.$"
            self.forward_zone_re = re.compile(forward_zone_re_base)
            self.forward_zone_re_components = re.findall(r"(%[a-z])", self.config["RecordPattern"])
            self.logger.debug("forward lookup for prefix %s will use %d components in this order %s" % (
                self.ip_network, len(self.forward_zone_re_components), ", ".join(self.forward_zone_re_components)))
            self.logger.debug("compiled forward lookup expression %s for prefix %s" % (forward_zone_re_base,
                                                                                       self.ip_network))
            self.logger.info("forward zone %s for prefix %s: loaded serial %d" % (self.config["ForwardZoneName"],
                                                                                  self.ip_network,
                                                                                  self.soa_record.times[0]))

        if not self.config["ForwardZoneEnabled"] and not self.config["ReverseZoneEnabled"]:
            raise PrefixException("reverse neither forward zone is enabled")

        self.static_entries = list()

        if "StaticEntries" in self.config:
            for sen, sed in self.config["StaticEntries"].items():
                try:
                    ent = dict()
                    ent["Address"] = ipaddress.ip_address(unicode(sen))
                    ent["ForwardLookup"] = True
                    ent["ReverseLookup"] = True
                    ent["RecordTTL"] = self.config["RecordTTL"]
                    if type(sed) in (str, unicode):
                        ent["Hostname"] = sed
                        if not ent["Address"] in self.ip_network:
                            raise ValueError("address out of prefix")
                    elif type(sed) is dict:
                        if not "Hostname" in sed:
                            raise ValueError("hostname is required")
                        ent["Hostname"] = sed["Hostname"]
                        ent["RecordTTL"] = sed["RecordTTL"] if "RecordTTL" in sed else ent["RecordTTL"]
                        ent["ForwardLookup"] = sed["ForwardLookup"] if "ForwardLookup" in sed else ent["ForwardLookup"]
                        ent["ReverseLookup"] = sed["ReverseLookup"] if "ReverseLookup" in sed else ent["ReverseLookup"]
                    else:
                        raise ValueError("configuration incorrect")
                    self.static_entries.append(ent)
                    self.logger.debug("prefix %s added static entry %s <-> %s (fl: %d, rl: %d, rttl: %d)" % (
                        self.ip_network, sen, ent["Hostname"], 1 if ent["ForwardLookup"] else 0,
                        1 if ent["ReverseLookup"] else 0, ent["RecordTTL"]))
                except ValueError as e:
                    self.logger.warn("prefix %s not loading static entry %s due to error: %s" % (self.ip_network, sen,
                                                                                                 e))
            self.logger.info("prefix %s loaded %d static entries" % (self.ip_network, len(self.static_entries)))
        pass

    def forward_match(self, request_name):
        request_name = unicode(request_name).lower()
        re_match = self.forward_zone_re.match(request_name.lower())
        if not re_match:
            return False

        if len(re_match.groups()) != len(self.forward_zone_re_components):
            return False

        prefix_hex = self.ip_network.network_address.exploded.replace(":", "")

        recovered_data = dict()

        for ck, cv in enumerate(self.forward_zone_re_components):
            ra_ip = None
            if cv == "%f":
                ra = unicode(re_match.groups()[ck])
                ra = ':'.join(ra[i:i + 4] for i in range(0, len(ra), 4))
                ra_ip = ipaddress.ip_address(ra)
                if not ra_ip in self.ip_network:
                    return False
            elif cv == "%r":
                ra_hex = ("0" * (self.ip_network.prefixlen / 4)) + re_match.groups()[ck]
                ra = unicode(hex(int(prefix_hex, 16) | int(ra_hex, 16))[2:])[:-1]
                ra = ':'.join(ra[i:i + 4] for i in range(0, len(ra), 4))
                ra_ip = ipaddress.ip_address(ra)
                if not ra_ip in self.ip_network:
                    return False
            if ra_ip is not None and "full_ip_address" in recovered_data and ra_ip != recovered_data["full_ip_address"]:
                return False
            else:
                recovered_data["full_ip_address"] = ra_ip

        return recovered_data

    def forward_resolve(self, request_name, request_type):
        if not self.config["ForwardZoneEnabled"]:
            raise PrefixException("prefix %s does not provide forward zone" % self.ip_network)
        records = list()
        if request_type == dnslib.QTYPE.SOA:
            if request_name != self.config["ForwardZoneName"] and not self.forward_match(request_name):
                raise RecordNotCoveredException("name %s does not belong to prefix %s" % (request_name,
                                                                                          self.ip_network))
            records.append(dnslib.RR(rname=self.config["ForwardZoneName"], rtype=dnslib.QTYPE.SOA,
                                     rclass=1, ttl=self.config["RecordTTL"],
                                     rdata=self.soa_record))
            for ns_record in self.ns_records:
                records.append(dnslib.RR(rname=self.config["ForwardZoneName"], rtype=dnslib.QTYPE.NS,
                                         rclass=1, ttl=self.config["RecordTTL"],
                                         rdata=ns_record))
            return records
        elif request_type == dnslib.QTYPE.NS:
            for ns_record in self.ns_records:
                records.append(dnslib.RR(rname=self.config["ForwardZoneName"], rtype=dnslib.QTYPE.NS,
                                         rclass=1, ttl=self.config["RecordTTL"],
                                         rdata=ns_record))
            return records
        elif request_type == dnslib.QTYPE.AAAA:
            static_entry = None
            for se in self.static_entries:
                if se["Hostname"] == request_name and se["ForwardLookup"]:
                    static_entry = se
                    break

            record_ttl = self.config["RecordTTL"]
            if static_entry is None:
                recovered_data = self.forward_match(request_name)
                if not recovered_data:
                    raise RecordNotCoveredException("name %s does not belong to prefix %s" % (request_name,
                                                                                              self.ip_network))
                if "full_ip_address" in recovered_data:
                    a4_data = recovered_data["full_ip_address"]
                else:
                    raise RecordNotCoveredException("name %s does not belong to prefix %s" % (request_name,
                                                                                              self.ip_network))
            else:
                a4_data = static_entry["Address"]
                record_ttl = static_entry["RecordTTL"]

            self.logger.debug("%s resolved to %s" % (request_name, a4_data))
            records = list()
            records.append(dnslib.RR(rname=request_name, rtype=dnslib.QTYPE.AAAA,
                                     rclass=1, ttl=record_ttl,
                                     rdata=dnslib.AAAA(unicode(a4_data))))
            return records
        else:
            raise PrefixException("unsupported record type %s" % dnslib.QTYPE[request_type])

    def reverse_resolve(self, request_name, ip_address, request_type):
        if not self.config["ReverseZoneEnabled"]:
            raise PrefixException("prefix %s does not provide reverse zone" % self.ip_network)
        if not ip_address in self.ip_network:
            raise RecordNotCoveredException("address %s is not within prefix %s" % (ip_address, self.ip_network))
        records = list()
        if request_type == dnslib.QTYPE.SOA:
            records.append(dnslib.RR(rname=self.reverse_zone_name, rtype=dnslib.QTYPE.SOA,
                                     rclass=1, ttl=self.config["RecordTTL"],
                                     rdata=self.soa_record))
            for ns_record in self.ns_records:
                records.append(dnslib.RR(rname=self.reverse_zone_name, rtype=dnslib.QTYPE.NS,
                                         rclass=1, ttl=self.config["RecordTTL"],
                                         rdata=ns_record))
            return records
        elif request_type == dnslib.QTYPE.PTR:
            static_entry = None
            for se in self.static_entries:
                if se["Address"] == ip_address and se["ReverseLookup"]:
                    static_entry = se
                    break
            record_ttl = self.config["RecordTTL"]
            if static_entry is None:
                remain_name = ip_address.exploded.replace(":", "")[self.ip_network.prefixlen / 4:]
                full_name = ip_address.exploded.replace(":", "")
                ptr_data = self.config["RecordPattern"]
                ptr_data = ptr_data.replace("%r", remain_name)
                ptr_data = ptr_data.replace("%f", full_name)
            else:
                ptr_data = static_entry["Hostname"]
                record_ttl = static_entry["RecordTTL"]

            self.logger.debug("%s resolved to %s" % (ip_address, ptr_data))
            records = list()
            records.append(dnslib.RR(rname=request_name, rtype=dnslib.QTYPE.PTR,
                                     rclass=1, ttl=record_ttl,
                                     rdata=dnslib.PTR(ptr_data)))
            return records
        else:
            raise PrefixException("unsupported record type %s" % dnslib.QTYPE[request_type])


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
            try:
                pfx_instance = Prefix(prefix, prefix_config)
                self.prefixes.append(pfx_instance)
            except PrefixException as e:
                self.logger.warn("not loading prefix %s due to error: %s" % (prefix, e))

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