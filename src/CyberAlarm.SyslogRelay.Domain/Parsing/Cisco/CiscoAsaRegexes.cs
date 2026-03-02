using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal static partial class CiscoAsaRegexes
{
    [GeneratedRegex(@"%ASA-(?:\w+-)?(?<severity>\d)-(?<message_id>\d{6}):\s+(?<message_content>.+)$", RegexOptions.Compiled)]
    public static partial Regex MainPattern();

    [GeneratedRegex(@"^Inbound\s+(?<protocol>TCP)\s+connection\s+denied\s+from\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106001();

    [GeneratedRegex(@"^Deny\s+inbound\s+(?<protocol>UDP)\s+from\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106006();

    [GeneratedRegex(@"^Deny\s+inbound\s+(?<protocol>UDP)\s+from\s+(?:\w+):(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+(?:\w+):(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106007();

    [GeneratedRegex(@"^Deny\s+inbound\s+(?<protocol>icmp)\s+src\s+(?:\w+):(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+dst\s+(?:\w+):(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})", RegexOptions.Compiled)]
    public static partial Regex Regex_106014();

    [GeneratedRegex(@"^Deny\s+(?<protocol>TCP)\s+\(no connection\)\s+from\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_106015();

    [GeneratedRegex(@"^(?<protocol>ICMP)\s+packet\s+from\s+(?:\w+):(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(?:\w+):(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})", RegexOptions.Compiled)]
    public static partial Regex Regex_106018();

    [GeneratedRegex(@"^Deny\s+(?<protocol>IP)\s+from\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})", RegexOptions.Compiled)]
    public static partial Regex Regex_106020();

    [GeneratedRegex(@"^Deny\s+protocol\s+(?<protocol_num>\d+)\s+reverse path check\s+from\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})", RegexOptions.Compiled)]
    public static partial Regex Regex_106021();

    [GeneratedRegex(@"^Deny\s+(?<protocol>\w+)\s+src\s+(?:[^:\s]+):(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+dst\s+(?:[^:\s]+):(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)\s+by\s+access-group\b.*$", RegexOptions.Compiled)]
    public static partial Regex Regex_106023();

    [GeneratedRegex(@"^access-list\s+\S+\s+(?<action>permitted|denied)\s+(?<protocol>\w+)\s+(?:\w+)/(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\((?<src_port>\d+)\)\s+->\s+(?:\w+)/(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\((?<dst_port>\d+)\)", RegexOptions.Compiled)]
    public static partial Regex Regex_106100();

    [GeneratedRegex(@"^Built\s+(?:in|out)bound\s+(?<protocol>TCP)\s+connection\s+\d+\s+for\s+\w+:(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+\([^)]+\)\s+to\s+\w+:(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302013();

    [GeneratedRegex(@"^Built\s+(?:in|out)bound\s+(?<protocol>UDP)\s+connection\s+\d+\s+for\s+\w+:(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+\([^)]+\)\s+to\s+\w+:(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302015();

    [GeneratedRegex(@"^Teardown\s+(?<protocol>UDP)\s+connection\s+\d+\s+for\s+\w+:(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+\w+:(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302016();

    [GeneratedRegex(@"^Teardown\s+(?<protocol>TCP)\s+connection\s+\d+\s+for\s+\w+:(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+\w+:(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_302014_303002();

    [GeneratedRegex(@"^Deny\s+(?<protocol>icmp)\s+src\s+(?:\w+):(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+dst\s+(?:\w+):(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})", RegexOptions.Compiled)]
    public static partial Regex Regex_313001();

    [GeneratedRegex(@"^IDS:\d+.*?from\s+(?:\w+):(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+(?:\w+):(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_400000_400050();

    [GeneratedRegex(@"^Embryonic limit exceeded.*?for\s+\w+:(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+\w+:(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_419001();

    [GeneratedRegex(@"^Dropping\s+(?<protocol>TCP)\s+embryonic connection\s+from\s+(?:\w+):(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<src_port>\d+)\s+to\s+(?:\w+):(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?<dst_port>\d+)", RegexOptions.Compiled)]
    public static partial Regex Regex_419002();

    [GeneratedRegex(@"^(?:\[[\w]+\])?\s*Host\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+is\s+attacking", RegexOptions.Compiled)]
    public static partial Regex Regex_733101();

    [GeneratedRegex(@"^(?:\[[\w]+\])?\s*Shunning\s+host\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})", RegexOptions.Compiled)]
    public static partial Regex Regex_733102();

    [GeneratedRegex(@"^(?:\[[\w]+\])?\s*Host\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+is\s+attacking\s+with\s+remote\s+access", RegexOptions.Compiled)]
    public static partial Regex Regex_733201();
}
