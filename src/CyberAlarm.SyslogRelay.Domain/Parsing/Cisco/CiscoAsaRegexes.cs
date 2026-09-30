using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal static partial class CiscoAsaRegexes
{
    [GeneratedRegex(@"(?:<\d+>:\s*)?%(?:ASA|FWSM|PIX)-(?:\w+-)?(?<severity>\d)-(?<message_id>\d{6}):\s+(?<message_content>.+)$", RegexOptions.Compiled)]
    public static partial Regex MainPattern();

    [GeneratedRegex(@"^Inbound\s+(?<protocol>TCP)\s+connection\s+denied\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<src_port>\d+)\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106001();

    [GeneratedRegex(@"^Deny\s+inbound\s+(?<protocol>UDP)\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<src_port>\d+)\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106006();

    [GeneratedRegex(@"^Deny\s+inbound\s+(?<protocol>UDP)\s+from\s+(?:[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+to\s+(?:[^:]+):(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106007();

    [GeneratedRegex(@"^Deny\s+inbound\s+(?<protocol>icmp)\s+src\s+(?:[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))\s+dst\s+(?:[^:]+):(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))", RegexOptions.Compiled)]
    public static partial Regex Regex_106014();

    [GeneratedRegex(@"^Deny\s+(?<protocol>TCP)\s+\(no connection\)\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<src_port>\d+)\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106015();

    [GeneratedRegex(@"^(?<protocol>ICMP)\s+packet\s+from\s+(?:[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))\s+to\s+(?:[^:]+):(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))", RegexOptions.Compiled)]
    public static partial Regex Regex_106018();

    [GeneratedRegex(@"^Deny\s+IP\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))", RegexOptions.Compiled)]
    public static partial Regex Regex_106020();

    [GeneratedRegex(@"^Deny\s+protocol\s+(?<protocol_num>\d+)\s+reverse path check\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))", RegexOptions.Compiled)]
    public static partial Regex Regex_106021();

    [GeneratedRegex(@"^Deny\s+(?:protocol\s+(?<protocol_num>\d+)|(?<protocol>\w+))\s+src\s+(?:[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))(?:/(?<src_port>\d+))?\s+dst\s+(?:[^:]+):(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))(?:/(?<dst_port>\d+))?(?:\s+\([^)]*\))?\s+by\s+access-group\b.*$", RegexOptions.Compiled)]
    public static partial Regex Regex_106023();

    [GeneratedRegex(@"^access-list\s+\S+\s+(?<action>permitted|denied)\s+(?<protocol>\w+)\s+(?:\w+)/(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\((?<src_port>\d+)\)\s+->\s+(?:\w+)/(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\((?<dst_port>\d+)\)", RegexOptions.Compiled)]
    public static partial Regex Regex_106100();

    [GeneratedRegex(@"^Built\s+(?<direction>in|out)bound\s+(?<protocol>TCP)\s+connection\s+\d+\s+for\s+[^:]+:(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+\([^)]+\)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302013();

    [GeneratedRegex(@"^Built\s+(?<direction>in|out)bound\s+(?<protocol>UDP)\s+connection\s+\d+\s+for\s+[^:]+:(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+\([^)]+\)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302015();

    [GeneratedRegex(@"^Teardown\s+(?<protocol>UDP)\s+connection\s+\d+\s+for\s+(?<first_iface>[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302016();

    [GeneratedRegex(@"^Teardown\s+(?<protocol>TCP)\s+connection\s+\d+\s+for\s+(?<first_iface>[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302014_303002();

    [GeneratedRegex(@"^(?:Deny\s+(?<protocol>icmp)\s+src\s+(?:[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))\s+dst\s+(?:[^:]+):(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))|Denied\s+ICMP\s+type=\d+,\s+code=\d+\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\s+on\s+interface\s+\w+)", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    public static partial Regex Regex_313001();

    [GeneratedRegex(@"^IDS:\d+.*?from\s+(?:[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+to\s+(?:[^:]+):(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_400000_400050();

    [GeneratedRegex(@"^Embryonic limit exceeded.*?for\s+[^:]+:(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_419001();

    [GeneratedRegex(@"^Dropping\s+(?<protocol>TCP)\s+embryonic connection\s+from\s+(?:[^:]+):(?:\[(?<src_ip>[0-9a-fA-F:]+)\]|(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<src_port>\d+)\s+to\s+(?:[^:]+):(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_419002();

    [GeneratedRegex(@"^(?:\[[\w]+\])?\s*Host\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\s+is\s+attacking", RegexOptions.Compiled)]
    public static partial Regex Regex_733101();

    [GeneratedRegex(@"^(?:\[[\w]+\])?\s*Shunning\s+host\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))", RegexOptions.Compiled)]
    public static partial Regex Regex_733102();

    [GeneratedRegex(@"^(?:\[[\w]+\])?\s*Host\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\s+is\s+attacking\s+with\s+remote\s+access", RegexOptions.Compiled)]
    public static partial Regex Regex_733201();

    [GeneratedRegex(@"^Deny\s+IP\s+spoof\s+from\s+\((?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\)\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))", RegexOptions.Compiled)]
    public static partial Regex Regex_106016();

    [GeneratedRegex(@"^Deny\s+IP\s+due\s+to\s+Land\s+Attack\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))", RegexOptions.Compiled)]
    public static partial Regex Regex_106017();

    [GeneratedRegex(@"^(?:Built\s+(?:in|out)bound|Teardown)\s+ICMP\s+connection\s+for\s+faddr\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/\d+(?:\(\d+\))?\s+gaddr\s+\S+\s+laddr\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))", RegexOptions.Compiled)]
    public static partial Regex Regex_302020_302021();

    [GeneratedRegex(@"^Denied\s+ICMP\s+type=\d+,\s+error\s+message\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))\s+on\s+interface\s+[^,\s]+(?:,\s+to\s+(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))?", RegexOptions.Compiled)]
    public static partial Regex Regex_313004();

    [GeneratedRegex(@"^(?<protocol>TCP|UDP)\s+access\s+denied\s+by\s+ACL\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<src_port>\d+)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_710001_710003();

    [GeneratedRegex(@"^TCP\s+access\s+permitted\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<src_port>\d+)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_710002();

    [GeneratedRegex(@"^(?<protocol>TCP|UDP)\s+request\s+discarded\s+from\s+(?<src_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}))/(?<src_port>\d+)\s+to\s+[^:]+:(?:\[(?<dst_ip>[0-9a-fA-F:]+)\]|(?<dst_ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})))/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_710005();
}
