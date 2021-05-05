# encoding: UTF-8

control 'V-230535' do
  title "RHEL 8 must prevent Internet Control Message Protocol (ICMP) redirect
messages from being accepted."
  desc  "ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages modify the
host's route table and are unauthenticated. An illicit ICMP redirect message
could result in a man-in-the-middle attack."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 will not accept ICMP redirect messages.

    Note: If either IPv4 or IPv6 is disabled on the system, this requirement
only applies to the active internet protocol version.

    Check the value of the default \"accept_redirects\" variables with the
following command:

    $ sudo sysctl net.ipv4.conf.default.accept_redirects
net.ipv6.conf.default.accept_redirects

    net.ipv4.conf.default.accept_redirects = 0
    net.ipv6.conf.default.accept_redirects = 0

    If the returned lines do not have a value of \"0\", or a line is not
returned, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to prevent ICMP redirect messages from being accepted with
the following command:

    $ sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

    $ sudo sysctl -w net.ipv6.conf.default.accept_redirects=0

    If \"0\" is not the system's default value then add or update the following
line in the appropriate file under \"/etc/sysctl.d\":

    net.ipv4.conf.default.accept_redirects=0

    net.ipv6.conf.default.accept_redirects=0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230535'
  tag rid: 'SV-230535r627750_rule'
  tag stig_id: 'RHEL-08-040210'
  tag fix_id: 'F-33179r568352_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
end

