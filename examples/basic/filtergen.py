import tomli
import tomli_w
import sys

DEFAULT_PKT_CONT = { 'Packet::Track': ['ipv4'] }
DEFAULT_PKT_DELIVER = {}
DEFAULT_SUBSCRIPTIONS = ['HttpTransaction', 'Connection']

NUM_SUBSCRIPTIONS = 1
EXP = "default"         # TODO: non-overlapping filters
INCLUDE_SESSIONS = False # TODO: False for comparison to baseline Retina

FP = 'filter_out.toml'

class CompleteFilter:
    def __init__(self):
        # Vec<String>: 
        # Subscribable datatypes
        self.subscriptions = []

        # <String, Vec<String>>: 
        # Packet Actions: filters (HW filter)
        self.packet_continue = {}
        # <String, Vec<String>>: 
        # Actions: filters
        self.packet_filter = {}   
        self.connection_filter = {}
        self.session_filter = {}

        # Vec<self.subscriptionspec>:
        # - filter, datatype, callback
        self.packet_deliver = {}
        self.connection_deliver = {}
        self.session_deliver = {}

        # String for "equivalent" filter
        self.as_str = ""

    def to_toml(self, fp):
        output = {}
        
        output = {
            "subscriptions": self.subscriptions,
            "packet_continue": self.packet_continue,
            "packet_filter": self.packet_filter,
            "connection_filter": self.connection_filter,
            "session_filter": self.session_filter,
            "packet_deliver": self.packet_deliver,
            "connection_deliver": self.connection_deliver,
            "session_deliver": self.session_deliver
        }

        empty = []
        for k in output:
            if not output[k]:
                empty.append(k)
        for k in empty:
            del output[k]

        with open(fp, 'wb') as f:
            tomli_w.dump(output, f)

    # def from_toml

    def populate_defaults(self):
        self.subscriptions = DEFAULT_SUBSCRIPTIONS
        self.packet_continue = DEFAULT_PKT_CONT
        self.packet_deliver = DEFAULT_PKT_DELIVER


class FilterValues:
    IP_CLIENT_SUBNET = 'ipv4.addr = 172.16.0.0/16'
    IP_CLIENT_START = 'ipv4.addr = 172.16.133.'
    IP_SERVER_SUBNET = 'ipv4.addr = 68.64.0.0/16'
    IP_SERVER_START = 'ipv4.addr = 68.64.0.'
    APPLICATION_PROTO = 'http'
    SESSION_FILTER = 'http.user_agent = \'asdfg\' and ' + IP_CLIENT_SUBNET

    DEF_CALLBACK = "default_cb"
    CONN_DATA = "Connection"
    APP_DATA = "HttpTransaction"

    def subscriptionspec(_self, fil, datatype, cb):
        return {"filter": fil, "datatype": datatype, "callback": cb }

    def gen_overlapping(self):
        subscriptions = CompleteFilter()
        subscriptions.populate_defaults()

        num_subscriptions = 0

        # --- Packet filter --- 
        # IPv4 and [app proto]
        APP_ACTIONS = "ConnFilter | ConnParse"
        subscriptions.packet_filter[APP_ACTIONS] = []
        subscriptions.packet_filter[APP_ACTIONS].append("ipv4")
        # IPV4 in subnets (client/server)
        CONN_ACTIONS = "ConnDataTrack (T)"
        subscriptions.packet_filter[CONN_ACTIONS] = []
        subscriptions.packet_filter[CONN_ACTIONS].append(self.IP_CLIENT_SUBNET)
        subscriptions.packet_filter[CONN_ACTIONS].append(self.IP_SERVER_SUBNET)

        # --- Connection filter (protocol) ---
        # Note: if app proto is just the proto + ipv4, no need to re-check IPv4 
        # if other preceding filters have removed IPv4

        # IPv4 and [app proto]
        subscriptions.connection_filter[CONN_ACTIONS] = [self.APPLICATION_PROTO]
        if INCLUDE_SESSIONS: 
            APP_ACTIONS = "SessionParse (T) | SessionDeliverConn (T)"
            subscriptions.connection_filter[APP_ACTIONS] = [self.APPLICATION_PROTO]
        
        # For session
        if INCLUDE_SESSIONS:
            SESSION_ACTIONS = "SessionParse | SessionFilter"
            subscriptions.connection_filter[SESSION_ACTIONS] = [self.APPLICATION_PROTO]
        

        # --- Session filter (parsed) ---
        # Deliver session on match
        if INCLUDE_SESSIONS:
            SESSION_ACTIONS = "SessionDeliver (T)"
            subscriptions.session_filter[SESSION_ACTIONS] = [self.SESSION_FILTER]

        # --- Connection deliver ---
        subscriptions.connection_deliver = []

        subscriptions.connection_deliver.append(
            self.subscriptionspec(self.IP_SERVER_SUBNET, self.CONN_DATA, self.DEF_CALLBACK)
        )
        num_subscriptions += 1
        subscriptions.as_str += "(" + self.IP_SERVER_SUBNET

        subscriptions.connection_deliver.append(
            self.subscriptionspec(self.IP_CLIENT_SUBNET, self.CONN_DATA, self.DEF_CALLBACK)
        )
        num_subscriptions += 1
        subscriptions.as_str += ") or (" + self.IP_CLIENT_SUBNET

        subscriptions.connection_deliver.append(
            self.subscriptionspec(self.APPLICATION_PROTO, self.CONN_DATA, self.DEF_CALLBACK)
        )
        subscriptions.as_str += ") or (" + self.APPLICATION_PROTO
        num_subscriptions += 1
        
        # TODO for x... num_subscriptions - individual ips/ports/etc

        # --- Session deliver ---
        if INCLUDE_SESSIONS:
            subscriptions.session_deliver = []
            subscriptions.session_deliver.append(
                self.subscriptionspec(self.APPLICATION_PROTO, self.APP_DATA, self.DEF_CALLBACK)
            )
            num_subscriptions += 1
            subscriptions.as_str += ") or (" + self.APPLICATION_PROTO

            subscriptions.session_deliver.append(
                self.subscriptionspec(self.SESSION_FILTER, self.APP_DATA, self.DEF_CALLBACK)
            )
            num_subscriptions += 1
            subscriptions.as_str += ") or (" + self.SESSION_FILTER

        subscriptions.as_str += ")"

        return subscriptions
        




if len(sys.argv) > 1:
    NUM_SUBSCRIPTIONS = int(sys.argv[1])

if len(sys.argv) > 2: 
    EXP = sys.argv[2]

generator = FilterValues()
subscriptions = generator.gen_overlapping()
print(subscriptions.as_str)
subscriptions.to_toml(FP)