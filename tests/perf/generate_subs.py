import argparse
import ipaddress
import tomli_w

class SubscriptionSpec:
    def __init__(self, addr): # TODO: enable passing in filter, datatypes, callback to make more flexible 
        self.filter = f"ipv4.addr = {addr}"
        self.datatypes = ["ConnRecord", "FilterStr"]
        self.callback = "ip_cb"
    
    def to_dict(self):
        return {
            "filter": self.filter,
            "datatypes": self.datatypes,
            "callback": self.callback,
        }

def shard_ipv4_addr_space(n):
    root = ipaddress.IPv4Network("0.0.0.0/0")

    # divide 0.0.0.0/0 into n subnets
    return list(root.subnets(new_prefix=int((n-1).bit_length())))

def generate_subs(n):
    subnets = shard_ipv4_addr_space(n)

    toml_content = {}
    toml_content["subscriptions"] = []
    for net in subnets:
        subscription = SubscriptionSpec(net.with_prefixlen)
        toml_content["subscriptions"].append(subscription.to_dict())

    out_file = "spec.toml"
    with open(out_file, "wb") as f:
        tomli_w.dump(toml_content, f)
    print(f"Generated {out_file} with {n} subscriptions")

def comma_sep_list(value):
    return value.split(',')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--num_subs", type=comma_sep_list)
    args = parser.parse_args()

    for num_subs in args.num_subs:
        generate_subs(int(num_subs))