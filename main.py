
from __future__ import print_function, unicode_literals, division
import socket, copy, time

from dnslib import DNSRecord

class Server(object):
    
    QR_QUERY = 0
    QR_RESPONSE = 1

    RCODE_NO_ERROR = 0

    MAX_DGRAM_SIZE = 512

    def __init__(self, server_addr, forwarders):
        self.forwarders = forwarders

        self.requests = {}
        self.cache = {}

        self.id_counter = 0
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # XXX: support IPv6
        self.s.bind(server_addr)

    def on_request(self, rec, request_addr, s):
        '''Process a request that came in from the client.'''

        # Attempt to respond from our cache
        cached = self.get_from_cache(rec)
        if cached:
            self.s.sendto(cached.pack(), request_addr)
            return

        # Save the original ID so we can send it back to the client later
        original_req_id = rec.header.id

        # Assign a new ID to this request that is unique to us
        self.id_counter = (self.id_counter + 1) % 0xffff
        rec.header.id = self.id_counter
        
        # Save this request so we can respond to the client later
        self.requests[rec.header.id] = original_req_id, request_addr # XXX: Structure this better. XXX: Save original request so we can request it again

        # Make the network request
        self.s.sendto(rec.pack(), self.forwarders[0]) # XXX: send to all

    def on_response(self, rec, s):
        '''Process a response we got from the upstream server.'''

        # If this is not our request, forget it
        if rec.header.id not in self.requests:
            return

        our_req_id = rec.header.id
        original_req_id, addr = self.requests[rec.header.id]

        # We are about to send this response back to the client,
        # so put the record ID back to what the client sent us
        rec.header.id = original_req_id
        self.s.sendto(rec.pack(), addr)

        self.add_to_cache(rec)

        # We are done with this request
        del self.requests[our_req_id]

    def get_from_cache(self, rec):
        '''Returns a DNSRecord response to the request specified by rec or None if response is not cached.'''

        now = time.time()
        key = (rec.q.qname, rec.q.qtype, rec.q.qclass)
        if key not in self.cache:
            return None

        cached = self.cache[key]

        if now > cached['expires']:
            return None

        header = copy.deepcopy(rec.header)
        header.rcode = cached['rcode']

        for r in cached['rr']:
            r.ttl = int(cached['expires'] - now)

        return DNSRecord(
            header=header,
            questions=rec.questions,
            rr=cached['rr'],
            ns=cached['ns'],
            ar=cached['ar'],
        )

    def add_to_cache(self, rec):
        '''Cache the response rec in our cache.'''

        # Do not cache responses with errors
        if rec.header.rcode != self.RCODE_NO_ERROR:
            return

        ttl = min(r.ttl for r in rec.rr)

        key = (rec.q.qname, rec.q.qtype, rec.q.qclass)
        cached = {
            'rr': tuple(rec.rr),
            'ns': tuple(),
            'ar': tuple(),
            'rcode': rec.header.rcode,
            'expires': time.time() + ttl,
        }

        if rec.ar:
            cached['ar'] = tuple(rec.ar)

        if rec.ns:
            cached['ns'] = tuple(rec.ns)

        self.cache[key] = cached

    def run(self):
        '''Serve requests from clients.'''

        # XXX: error handling
        # XXX: signal handling
        # XXX: stop server
        # XXX: re-running requests

        while True:
            data, addr = self.s.recvfrom(self.MAX_DGRAM_SIZE)

            rec = DNSRecord.parse(data)

            qr = rec.header.get_qr()
            
            if qr == self.QR_RESPONSE:
                self.on_response(rec, self.s)

            elif qr == self.QR_QUERY:
                self.on_request(rec, addr, self.s)


if __name__ == '__main__':
    Server(('0.0.0.0', 5553), [('8.8.4.4', 53), ('8.8.8.8', 53)]).run()

