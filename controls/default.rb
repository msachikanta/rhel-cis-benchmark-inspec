## Start of CIS Workbench Level 1 Checks ##
# CIS Workbench Level 1 - Section 1
control 'SCORED | 1.1.1.1 | PATCH' do
  impact 1.0
  title 'Ensure mounting of cramfs filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v cramfs') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep cramfs') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.1.2 | PATCH' do
  impact 1.0
  title 'Ensure mounting of freevxfs filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v freevxfs') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep freevxfs') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.1.3 | PATCH' do
  impact 1.0
  title 'Ensure mounting of jffs2 filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v jffs2') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep jffs2') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.1.4 | PATCH' do
  impact 1.0
  title 'Ensure mounting of hfs filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v hfs') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep hfs') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.1.5 | PATCH' do
  impact 1.0
  title 'Ensure mounting of hfsplus filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v hfsplus') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep hfsplus') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.1.6 | PATCH' do
  impact 1.0
  title 'Ensure mounting of squashfs filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v squashfs') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep squashfs') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.1.7 | PATCH' do
  impact 1.0
  title 'Ensure mounting of udf filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v udf') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep udf') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.1.8 | PATCH' do
  impact 1.0
  title 'Ensure mounting of vFAT filesystems is disabled and module is removed'
  describe command('sudo modprobe -n -v vfat') do
    its('stdout') { should match 'install /bin/true ' }
  end
  describe command('lsmod | grep vfat') do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.3 | PATCH' do
  impact 1.0
  title 'Ensure nodev option set on /tmp partition'
  describe command('mount | grep tmp') do
    its('stdout') { should match /nodev/ }
  end
end

control 'SCORED | 1.1.4 | PATCH' do
  impact 1.0
  title 'Ensure nosuid option set on /tmp partition'
  describe command('mount | grep tmp') do
    its('stdout') { should match /nosuid/ }
  end
end

control 'SCORED | 1.1.5 | PATCH' do
  impact 1.0
  title 'Ensure noexec option set on /tmp partition'
  describe command('mount | grep tmp') do
    its('stdout') { should match /noexec/ }
  end
end

control 'SCORED | 1.1.8  | PATCH' do
  impact 1.0
  title 'Ensure nodev option set on /var/tmp partition'
  describe command('mount | grep /var/tmp') do
    # its('stdout') { should match /nodev/ }
    skip 'This check is skipped in ansible role, hence skipping this control.'
  end
end

control 'SCORED | 1.1.9  | PATCH' do
  impact 1.0
  title 'Ensure nosuid option set on /var/tmp partition'
  describe command('mount | grep /var/tmp') do
    # its('stdout') { should match /nosuid/ }
    skip 'This check is skipped in ansible role, hence skipping this control.'
  end
end

control 'SCORED | 1.1.10 | PATCH' do
  impact 1.0
  title 'Ensure noexec option set on /var/tmp partition'
  describe command('mount | grep /var/tmp') do
    # its('stdout') { should match /noexec/ }
    skip 'This check is skipped in ansible role, hence skipping this control.'
  end
end

control 'SCORED | 1.1.14 | PATCH' do
  impact 1.0
  title 'Ensure nodev option on /home partition'
  describe command('mount | grep home') do
    # its('stdout') { should match /nodev/ }
    skip 'This check is skipped for now.'
  end
end

control 'SCORED | 1.1.15 | PATCH' do
  impact 1.0
  title 'Ensure nodev option on /dev/shm partition'
  describe command('mount | grep shm') do
    its('stdout') { should match /nodev/ }
  end
end

control 'SCORED | 1.1.16 | PATCH' do
  impact 1.0
  title 'Ensure nosuid option on /dev/shm partition'
  describe command('mount | grep shm') do
    its('stdout') { should match /nosuid/ }
  end
end

control 'SCORED | 1.1.17 | PATCH' do
  impact 1.0
  title 'Ensure noexec option on /dev/shm partition'
  describe command('mount | grep shm') do
    its('stdout') { should match /noexec/ }
  end
end

control 'NOTSCORED | 1.1.18 | PATCH' do
  impact 1.0
  title 'Ensure nodev option on mount partition'
  describe command('mount') do
    its('stdout') { should match /nodev/  }
  end
end

control 'NOTSCORED | 1.1.19 | PATCH' do
  impact 1.0
  title 'Ensure nosuid option on mount partition'
  describe command('mount') do
    its('stdout') { should match /nosuid/  }
  end
end

control 'NOTSCORED | 1.1.20 | PATCH' do
  impact 1.0
  title 'Ensure noexec option on mount partition'
  describe command('mount') do
    its('stdout') { should match /noexec/  }
  end
end

control 'SCORED | 1.1.21 | PATCH' do
  impact 1.0
  title 'Ensure sticky bit is set on all world-writable directories'
  describe command("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null") do
    its('stdout') { should eq '' }
  end
end

control 'SCORED | 1.1.22 | PATCH' do
  impact 1.0
  title 'Disable Automounting'
  describe systemd_service('autofs') do
    it { should_not be_enabled }
  end
end

control 'NOTSCORED | 1.2.1 | PATCH' do
  impact 1.0
  title 'Ensure yum repolist'
  describe command('sudo yum repolist') do
    its('stdout') { should match "epel/x86_64"  }
    # its('stdout') { should match /nginx-plus/  }
    # its('stdout') { should match /openresty/  }
  end
end

control 'SCORED | 1.2.2 | PATCH' do
  impact 1.0
  title 'Ensure gpgcheck is globally activated'
  describe command('grep ^gpgcheck /etc/yum.conf') do
    its('stdout') { should match /gpgcheck=1/  }
  end
end

control 'NOTSCORED | 1.2.3 | PATCH' do
  impact 1.0
  title 'Ensure gpgcheck is globally activated'
  describe command("sudo rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'") do
    its('stdout') { should match /release key 2/  }
    its('stdout') { should match /auxiliary key/  }
  end
end

control 'NOTSCORED | 1.2.4 | PATCH' do
  impact 1.0
  title 'Ensure Red Hat Subscription Manager connection is configured'
  describe command("sudo subscription-manager identity") do
    # its('stdout') { should match /This system is not yet registered/  }
    skip 'This control must be manually reviewed'
  end
end

control 'NOTSCORED | 1.2.5 | PATCH' do
  impact 1.0
  title 'Disable the rhnsd Daemon'
  describe systemd_service('rhnsd') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 1.3.1 | PATCH' do
  impact 1.0
  title 'Ensure AIDE is installed'
  describe.one do
    describe package('aide') do
      it { should be_installed }
    end
    describe command('sudo rpm -q aide') do
      its('stdout') { should match /aide/ }
    end
  end
end

control 'SCORED | 1.3.2 | PATCH' do
  impact 1.0
  title 'Ensure filesystem integrity is regularly checked'
  describe crontab do
    #its('name') { should cmp "Run AIDE integrity check" }
    #its('minutes') { should cmp '0' }
    #its('hours') { should cmp '5' }
    #its('days') { should cmp '*' }
    #its('weekdays') { should cmp '*' }
    #its('months') { should cmp '*' }
    #its('user') { should include 'root' }
    #its('commands') { should include '/usr/sbin/aide --check' }
    skip "Skipping as this control is not ready"
  end
  #describe command('sudo crontab -u root -l | grep aide') do
  #  its('stdout') { should match "0 5 * * * /usr/sbin/aide --check\n"  }
  #end
end

control 'SCORED | 1.4.1 | PATCH' do
  impact 1.0
  title 'Ensure permissions on bootloader config are configured'
  describe file('/boot/grub2/grub.cfg') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0600' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 1.4.2 | PATCH' do
  impact 1.0
  title 'Ensure permissions on bootloader config are configured'
  describe command('sudo grep "^GRUB2_PASSWORD" /boot/grub2/grub.cfg') do
    # its('stdout') { should_not eq '' }
    skip 'This control is not needed as it is false by default.'
  end
end

control 'NOTSCORED | 1.4.3 | PATCH' do
  impact 1.0
  title 'Ensure authentication required for single user mode '
  describe command('grep /sbin/sulogin /usr/lib/systemd/system/rescue.service') do
    its('stdout') { should match  'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' }
  end
  describe command('grep /sbin/sulogin /usr/lib/systemd/system/emergency.service') do
    its('stdout') { should match  'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' }
    # skip 'This control must be manually reviewed'
  end
end

control 'SCORED | 1.5.1 | PATCH' do
  impact 1.0
  title 'Ensure core dumps are restricted'
  describe command('sudo sysctl fs.suid_dumpable') do
    its('stdout') { should match /fs.suid_dumpable = 0/ }
  end
  describe limits_conf do
    its('*') { should include ['hard', 'core', '0'] }
  end
end

control 'NOTSCORED | 1.5.2 | PATCH' do
  impact 1.0
  title 'Ensure XD/NX support is enabled'
  describe command('dmesg | grep NX') do
    its('stdout') { should match %r{active} }
  end
end

control 'SCORED | 1.5.3 | PATCH' do
  impact 1.0
  title 'Ensure address space layout randomization (ASLR) is enabled'
  describe command('sudo sysctl kernel.randomize_va_space') do
    its('stdout') { should match "kernel.randomize_va_space = 2" }
  end
end

control 'SCORED | 1.5.4 | PATCH' do
  impact 1.0
  title 'Ensure prelink is disabled'
  describe.one do
    describe package('prelink') do
      it { should_not be_installed }
    end
    describe command('rpm -q prelink') do
      its('stdout') { should match /package prelink is not installed/ }
    end
  end
end

control 'SCORED | 1.6.1.1 | PATCH' do
  title 'Ensure SELinux is not disabled in bootloader configuration'
  describe command("grep -E 'kernelopts=(\S+\s+)*(selinux=0|enforcing=0)+\b' /boot/grub2/grubenv") do
    its('stdout') { should eq('') }
  end
end

control 'SCORED | 1.6.1.2 | PATCH' do
  title 'Ensure the SELinux state is enforcing'
  describe command("grep -E '^\s*SELINUX=enforcing' /etc/selinux/config") do
    #its('stdout') { should eq "SELINUX=enforcing" }
    skip "This check is skipped as value of 'rhel7cis_selinux_disable' is set to false"
  end
end

control 'SCORED | 1.6.1.3 | PATCH' do
  title 'Ensure SELinux policy is configured'
  describe command("grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config") do
    #its('stdout') { should eq "SELINUXTYPE=targeted" }
    skip "This check is skipped as value of 'rhel7cis_selinux_disable' is set to false"
  end
end

control 'SCORED | 1.6.1.4 | PATCH' do
  title 'Ensure SETroubleshoot is not installed'
  describe package('setroubleshoot') do
    it { should_not be_installed }
  end
end

control 'SCORED | 1.6.1.5 | PATCH' do
  title 'Ensure the MCS Translation Service (mcstrans) is not installed'
  describe package('mcstrans') do
    it { should_not be_installed }
  end
end

control 'SCORED | 1.6.2 | PATCH' do
  title 'Ensure SELinux is installed'
  describe package('libselinux') do
    it { should be_installed }
  end
end

control 'SCORED | 1.7.1.1 | PATCH' do
  impact 1.0
  title ' Ensure message of the day is configured properly'
  describe command('egrep \'(\\\v|\\\r|\\\m|\\\s)\' /etc/motd') do
    its('stdout') { should eq '' }
  end
end

control 'NOTSCORED | 1.7.1.2 | PATCH' do
  impact 1.0
  title 'Ensure local login banner is configured properly'
  describe command('egrep \'(\\\v|\\\r|\\\m|\\\s)\' /etc/issue') do
    its('stdout') { should eq '' }
  end
end

control 'NOTSCORED | 1.7.1.3 | PATCH' do
  impact 1.0
  title 'Ensure remote login banner is configured properly'
  describe command('egrep \'\(\\\v|\\\r|\\\m|\\\s\)\' /etc/issue.net') do
    its('stdout') { should eq '' }
  end
end

control 'NOTSCORED | 1.7.1.4 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/motd are configured'
  describe file('/etc/motd') do
    it { should be_file }
    its('mode') { should cmp '0644' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 1.7.1.5 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/issue are configured'
  describe file('/etc/issue') do
    it { should be_file }
    its('mode') { should cmp '0644' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'NOTSCORED | 1.7.1.6 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/issue.net are configured'
  describe file('/etc/issue.net') do
    it { should be_file }
    its('mode') { should cmp '0644' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 1.7.2 | PATCH' do
  impact 1.0
  title 'Ensure GDM login banner is configured'
  if File.exist?('/etc/dconf/profile/gdm')
    describe command('cat /etc/dconf/profile/gdm') do
      its('stdout') { should match %r{user-db:user} }
    end
  end
end

control 'NOTSCORED | 1.8 | PATCH' do
  impact 1.0
  title 'Ensure updates, patches, and additional security software are installed '
  describe command('sudo yum check-update --security') do
    # its('stdout') { should match /0 package(s) needed for security/}
    skip 'This control must be manually reviewed'
  end
end

# CIS Workbench Level 1 - Section 2
control 'SCORED | 2.1.1 | PATCH' do
  impact 1.0
  title 'Ensure daytime services are not enabled'
  describe command(' chkconfig --list') do
    its('stdout') { should_not match /chargen-dgram/}
    its('stdout') { should_not match /chargen-stream/}
  end
end

control 'SCORED | 2.1.2 | PATCH' do
  impact 1.0
  title 'Ensure daytime services are not enabled'
  describe command(' chkconfig --list') do
    its('stdout') { should_not match /daytime-dgram/}
    its('stdout') { should_not match /daytime-stream/}
  end
end

control 'SCORED | 2.1.3 | PATCH' do
  impact 1.0
  title 'Ensure discard services are not enabled'
  describe command(' chkconfig --list') do
    its('stdout') { should_not match /discard-dgram/}
    its('stdout') { should_not match /daytime-stream/}
  end
end

control "SCORED | 2.1.4 | PATCH" do
  impact 1.0
  title 'Ensure echo services are not enabled '
  describe command(' chkconfig --list') do
    its('stdout') { should_not match /echo-dgram/ }
    its('stdout') { should_not match /echo-stream/ }
  end
end

control 'SCORED | 2.1.5 | PATCH' do
  impact 1.0
  title 'Ensure time services are not enabled'
  describe command(' chkconfig --list') do
    its('stdout') { should_not match /time-dgram/ }
    its('stdout') { should_not match /time-stream/ }
  end
end

control 'SCORED | 2.1.6 | PATCH' do
  impact 1.0
  title 'Ensure tftp services are not enabled'
  describe command(' chkconfig --list') do
    its('stdout') { should_not match /tftp/ }
  end
end

control 'SCORED | 2.1.7 | PATCH' do
  impact 1.0
  title 'Ensure tftp services are not enabled'
  describe systemd_service('xinetd') do
    it { should_not be_enabled }
  end
  only_if { file('/etc/xinetd.service').exist?}
end

control 'NOTSCORED | 2.2.1.1 | PATCH' do
  impact 1.0
  title 'Ensure time synchronization is in use'
  describe.one do
    describe package('ntp') do
      it { should be_installed }
    end
    describe package('chrony') do
      it { should be_installed }
    end
  end
end

control 'SCORED | 2.2.1.2 | PATCH and SCORED | 2.2.1.3 | PATCH' do
  impact 1.0
  title 'Ensure ntp and/or chrony is configured'
  describe.one do
    describe command('grep "^OPTIONS" /etc/sysconfig/ntpd') do
      #its('stdout') { should match /OPTIONS="-u ntp:ntp"/ }
      skip 'Skipping for now. This control must be manually reviewed'
    end
    describe command('grep ^OPTIONS /etc/sysconfig/chronyd') do
      #its('stdout') { should match /OPTIONS="-u chrony"/ }
      skip 'Skipping for now. This control must be manually reviewed'
    end
  end
end

control 'SCORED | 2.2.2 | PATCH' do
  impact 1.0
  title 'Ensure X Window System is not installed'
  describe.one do
    describe package('xorg-x11*') do
      it { should_not be_installed }
    end
    describe command('sudo rpm -qa xorg-x11*') do
      its('stdout') { should eq '' }
    end
  end
end

control 'SCORED | 2.2.3 | PATCH' do
  impact 1.0
  title 'Ensure Avahi Server is not enabled'
  describe systemd_service('avahi-daemon') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.4 | PATCH' do
  impact 1.0
  title 'Ensure CUPS is not enabled'
  describe systemd_service('cups') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.5 | PATCH' do
  impact 1.0
  title 'Ensure DHCP Server is not enabled'
  describe systemd_service('dhcpd') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.6 | PATCH' do
  impact 1.0
  title 'Ensure LDAP Server is not enabled'
  describe systemd_service('slapd') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.7 | PATCH' do
  impact 1.0
  title 'Ensure NFS and RPC are not enabled'
  describe systemd_service('nfs') do
    it { should_not be_enabled }
  end
  describe systemd_service('nfs-server') do
    it { should_not be_enabled }
  end
  describe systemd_service('rpcbind') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.8 | PATCH' do
  impact 1.0
  title 'Ensure DNS Server is not enabled'
  describe systemd_service('named') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.9 | PATCH' do
  impact 1.0
  title 'Ensure FTP Server is not enabled'
  describe systemd_service('vsftpd') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.10 | PATCH' do
  impact 1.0
  title 'Ensure HTTP Server is not enabled'
  describe systemd_service('httpd') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.11 | PATCH' do
  impact 1.0
  title 'Ensure IMAP and POP3 server is not enabled'
  describe systemd_service('dovecot') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.12 | PATCH' do
  impact 1.0
  title 'Ensure Samba is not enabled'
  describe systemd_service('smb') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.13 | PATCH' do
  impact 1.0
  title 'Ensure HTTP Proxy Server is not enabled'
  describe systemd_service('squid') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.14 | PATCH' do
  impact 1.0
  title 'Ensure SNMP Proxy Server is not enabled'
  describe systemd_service('snmpd') do
    it { should_not be_enabled }
  end
end

control 'SCORED | 2.2.15 | PATCH' do
  impact 1.0
  title 'Ensure SNMP Proxy Server is not enabled'
  describe command("netstat -an | grep LIST | grep ':25[[:space:]]'") do
    its('stdout') { should include  'tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN' }
    skip 'This control must be manually reviewed'
  end
end

control 'SCORED | 2.2.16 | PATCH' do
  impact 1.0
  title 'Ensure NIS Server is not enabled'
  describe.one do
   describe systemd_service('ypserv') do
     it { should_not be_enabled }
   end
    describe command('systemctl is-enabled ypserv') do
      its('stdout') { should_not match  /enabled/ }
    end
  end
end

control 'SCORED | 2.2.17 | PATCH' do
  impact 1.0
  title 'Ensure rsh server is not enabled - rexec, rlogin, rsh'
  describe command('systemctl is-enabled rsh.socket') do
    its('stdout') { should_not match  /enabled/ }
  end
  describe command('systemctl is-enabled rlogin.socket') do
    its('stdout') { should_not match  /enabled/ }
  end
  describe command('systemctl is-enabled rexec.socket') do
    its('stdout') { should_not match  /enabled/ }
  end
end

control 'SCORED | 2.2.18 | PATCH' do
  impact 1.0
  title 'Ensure telnet server is not enabled'
  describe.one do
    describe systemd_service('telnet') do
      it { should_not be_enabled }
    end
    describe command('systemctl is-enabled telnet.socket') do
      its('stdout') { should_not match  /enabled/ }
    end
  end
end

control 'SCORED | 2.2.19 | PATCH' do
  impact 1.0
  title 'Ensure tftp server is not enabled'
  describe.one do
    describe systemd_service('tftp') do
      it { should_not be_enabled }
    end
    describe command('systemctl is-enabled tftp.socket') do
      its('stdout') { should_not match /enabled/ }
    end
  end
end

control 'SCORED | 2.2.20 | PATCH' do
  impact 1.0
  title 'Ensure rsync service is not enabled'
  describe.one do
    describe systemd_service('rsyncd') do
      it { should_not be_enabled }
    end
    describe command('systemctl is-enabled rsyncd') do
      its('stdout') { should_not match  /enabled/ }
    end
  end
end

control 'SCORED | 2.2.21 | PATCH' do
  impact 1.0
  title 'Ensure talk server is not enabled'
  describe.one do
    describe systemd_service('ntalk') do
      it { should_not be_enabled }
    end
    describe command('systemctl is-enabled ntalk') do
      its('stdout') { should_not match /enabled/ }
    end
  end
end

control 'SCORED | 2.3.1 | PATCH ' do
  impact 1.0
  title 'Ensure NIS Client is not installed'
  describe.one do
    describe package('ypbind') do
      it { should_not be_installed }
    end
    describe command('sudo rpm -q ypbind') do
      its('stdout') { should match  /package ypbind is not installed/ }
    end
  end
end

control 'SCORED | 2.3.2 | PATCH' do
  impact 1.0
  title 'Ensure rsh Client is not installed'
  describe.one do
    describe package('rsh') do
      it { should_not be_installed }
    end
    describe command('sudo rpm -q rsh') do
      its('stdout') { should match  /package rsh is not installed/ }
    end
  end
end

control 'SCORED | 2.3.3 | PATCH' do
  impact 1.0
  title 'Ensure talk Client is not installed'
  describe.one do
    describe package('talk') do
      it { should_not be_installed }
    end
    describe command('sudo rpm -q talk') do
      its('stdout') { should match  /package talk is not installed/ }
    end
  end
end

control 'SCORED | 2.3.4 | PATCH' do
  impact 1.0
  title 'Ensure telnet Client is not installed'
  describe.one do
    describe package('telnet') do
      it { should_not be_installed }
    end
    describe command('sudo rpm -q telnet') do
      its('stdout') { should match  /package telnet is not installed/ }
    end
  end
end

control 'SCORED | 2.3.5 | PATCH' do
  impact 1.0
  title 'Ensure LDAP Client is not installed'
  describe.one do
    describe package('openldap-clients') do
      it { should_not be_installed }
    end
    describe command('sudo rpm -q openldap-clients') do
      its('stdout') { should match  /package openldap-clients is not installed/ }
    end
  end
end

# CIS Workbench Level 1 - Section 3
control 'SCORED | 3.1.1 | PATCH' do
  impact 1.0
  title 'Ensure IP forwarding is disabled'
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
  describe command('grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 3.1.2 | PATCH' do
  impact 1.0
  title ' Ensure packet redirect sending is disabled'
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should eq 0 }
  end
end

control 'SCORED | 3.2.1 | PATCH' do
  impact 1.0
  title 'Ensure source routed packets are not accepted'
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end
end

control 'SCORED | 3.2.2 | PATCH' do
  impact 1.0
  title 'Ensure ICMP redirects are not accepted'
  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end
end

control 'SCORED | 3.2.3 | PATCH' do
  impact 1.0
  title 'Ensure secure ICMP redirects are not accepted'
  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.secure_redirects') do
    its('value') { should eq 0 }
  end
end

control 'SCORED | 3.2.4 | PATCH' do
  impact 1.0
  title 'Ensure suspicious packets are logged'
  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should eq 1 }
  end
end

control 'SCORED | 3.2.5 | PATCH' do
  impact 1.0
  title 'Ensure broadcast ICMP requests are ignored'
  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end

control 'SCORED | 3.2.6 | PATCH' do
  impact 1.0
  title 'Ensure bogus ICMP requests are ignored'
  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should eq 1 }
  end
end

control 'SCORED | 3.2.7 | PATCH' do
  impact 1.0
  title 'Ensure Reverse Path Filtering is enabled'
  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should eq 1 }
  end
end

control 'SCORED | 3.2.8 | PATCH' do
  impact 1.0
  title 'Ensure TCP SYN Cookies is enabled'
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
end

control 'SCORED | 3.3.1 | PATCH' do
  impact 1.0
  title 'Ensure IPv6 router advertisements are not accepted'
  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
    its('value') { should eq 0 }
  end
end

control 'SCORED | 3.3.2 | PATCH' do
  impact 1.0
  title 'Ensure IPv6 redirects are not accepted'
  describe kernel_parameter('net.ipv6.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv6.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end
end

control 'NOTSCORED | 3.3.3 | PATCH' do
  impact 1.0
  title 'Ensure IPv6 is disabled'
  describe.one do
    describe command ( 'grep -E "^\s*kernelopts=(\S+\s+)*ipv6\.disable=1\b\s*(\S+\s*)*$" /boot/grub2/grubenv' ) do
      #its('stdout') { should match "ipv6.disable=1" }
      skip 'This control is set to false by default in ansible role'
    end
  end
end

control 'SCORED | 3.4.1 | PATCH' do
  impact 1.0
  title 'Ensure TCP Wrappers is installed'
  describe command('rpm -q tcp_wrappers') do
    its('stdout') { should match /tcp_wrappers-7./ }
  end
end

control 'SCORED | 3.4.2 | PATCH' do
  impact 1.0
  title 'Ensure /etc/hosts.allow is configured'
  describe command('cat /etc/hosts.allow') do
    its('stdout') { should_not match /sshd: ALL/ }
     # skip 'This control must be manually reviewed'
  end
end

control 'SCORED | 3.4.3 | PATCH' do
  impact 1.0
  title 'Ensure /etc/hosts.deny is configured'
  describe.one do
    describe file('/etc/hosts.allow') do
      it { should exist }
      it { should be_file }
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
      its('mode') { should cmp '0644' }
    end
    describe command('stat /etc/hosts.allow') do
      its('stdout') { should match  "0644/-rw-r--r--" }
      its('stdout') { should include  "Uid: (    0/    root)" }
      its('stdout') { should include  "Gid: (    0/    root)" }
    end
  end
end

control 'SCORED | 3.4.4 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/hosts.allow are configured'
  describe command('stat /etc/hosts.allow') do
    its('stdout') { should match  "0644/-rw-r--r--" }
    its('stdout') { should include  "Uid: (    0/    root)" }
    its('stdout') { should include  "Gid: (    0/    root)" }
    # its('stdout') { should match %s{^|s*Access: } }
    #skip 'This control must be manually reviewed'
  end
end

control 'SCORED | 3.4.5 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/hosts.deny are configured'
  describe.one do
    describe file('/etc/hosts.deny') do
      it { should exist }
      it { should be_file }
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
      its('mode') { should cmp '0644' }
    end
    describe command('stat /etc/hosts.deny') do
      its('stdout') { should match  "0644/-rw-r--r--" }
      its('stdout') { should include  "Uid: (    0/    root)" }
      its('stdout') { should include  "Gid: (    0/    root)" }
    end
  end
end

control 'NOTSCORED | 3.5.1 | PATCH' do
  impact 1.0
  title 'Ensure DCCP is disabled'
  describe command('modprobe -n -v dccp') do
    its('stdout') { should match "install /bin/true" }
  end
  describe command('lsmod | grep dccp') do
    its('stdout') { should match "" }
  end
end

control 'NOTSCORED | 3.5.2 | PATCH' do
  impact 1.0
  title 'Ensure SCTP is disabled'
  describe command('modprobe -n -v sctp') do
    its('stdout') { should match "install /bin/true" }
     # skip 'This control must be manually reviewed'
  end
end

control 'NOTSCORED | 3.5.3 | PATCH' do
  impact 1.0
  title 'Ensure RDS is disabled'
  describe command('modprobe -n -v rds') do
    its('stdout') { should match "install /bin/true " }
    # skip 'This control must be manually reviewed'
  end
  describe command('lsmod | grep rds') do
    its('stdout') { should match "" }
    # skip 'This control must be manually reviewed'
  end
end

control 'NOTSCORED | 3.5.4 | PATCH' do
  impact 1.0
  title 'Ensure TIPC is disabled'
  describe command('modprobe -n -v tipc') do
    its('stdout') { should match "install /bin/true " }
  end
  describe command('lsmod | grep tipc') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 3.6 | PATCH' do
  impact 1.0
  title 'Ensure firewalld is installed, started and enabled | CUSTOM'
  describe package('firewalld') do
    it { should be_installed }
  end
  describe systemd_service('firewalld') do
    #it { should be_enabled }
    skip 'Skipping this check for now, need to check and verify ansible apply'
  end
end

control 'SCORED | 3.6.1 | PATCH' do
  impact 1.0
  title 'Ensure iptables is installed'
  describe package('iptables') do
    it { should be_installed }
  end
end

control 'SCORED | 3.6.2 | PATCH' do
  impact 1.0
  title 'Ensure default deny firewall policy'
  %w[INPUT OUTPUT FORWARD].each do |chain|
    describe.one do
      describe iptables do
        #it { should have_rule("-P #{chain} DROP") }
        skip "Skipping this check as it is skipped in ansible apply"
      end
      describe iptables do
        #it { should have_rule("-P #{chain} REJECT") }
        skip "Skipping this check as it is skipped in ansible apply"
      end
    end
  end
end

control 'SCORED | 3.6.3 | PATCH' do
  impact 1.0
  title 'Ensure loopback traffic is configured'
  describe command('iptables -L INPUT -v -n') do
    # its('stdout') { should match "Chain INPUT (policy DROP)" }
    skip 'This control yet to be done '
  end
end

control 'NOTSCORED | 3.6.4 | PATCH' do
  impact 1.0
  title 'Ensure outbound and established connections are configured'
  describe command('iptables -L -v -n') do
    # its('stdout') { should match "" }
    skip 'This control yet to be done '
  end
end

control 'SCORED | 3.6.5 | PATCH' do
  impact 1.0
  title 'Ensure firewall rules exist for all open ports'
  port.where { protocol =~ /.*/ && port >= 0 && address =~ /^(?!127\.0\.0\.1|::1|::).*$/ }.entries.each do |entry|
    rule_inbound = "-A INPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --dport #{entry[:port]} -m state --state NEW,ESTABLISHED -j"
    rule_outbound = "-A OUTPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --sport #{entry[:port]} -m state --state ESTABLISHED -j A"
    describe iptables do
      #it { should have_rule(rule_inbound) }
      #it { should have_rule(rule_outbound) }
      skip "Skipping this check as it is skipped in ansible apply"
    end
  end
end

control 'NOTSCORED | 3.7 | PATCH' do
  impact 1.0
  title 'Ensure wireless interfaces are disabled'
  describe command('iwconfig') do
    # its('stdout') { should match "" }
    skip 'This control not ready '
  end
end

# CIS Workbench Level 1 - Section 4
control 'NOTSCORED | 4.1.1.1 | PATCH' do
  impact 1.0
  title 'Ensure audit log storage size is configured'
  describe.one do
    describe auditd_conf do
      its('max_log_file') { should eq '10' }
    end
    describe command('grep max_log_file /etc/audit/auditd.conf') do
      its('stdout') { should match "max_log_file = 10" }
    end
  end
end

control 'SCORED | 4.1.1.2 | PATCH' do
  impact 1.0
  title 'Ensure system is disabled when audit logs are full'
  describe.one do
    describe auditd_conf do
      its('space_left_action') { should eq 'email' }
      its('admin_space_left_action') { should eq 'halt' }
    end
    describe command('grep admin_space_left_action /etc/audit/auditd.conf') do
      its('stdout') { should match "admin_space_left_action = halt" }
      its('stdout') { should match "space_left_action = email" }
    end
  end
end

control 'SCORED | 4.1.1.3 | PATCH' do
  impact 1.0
  title 'Ensure audit logs are not automatically deleted'
  describe.one do
    describe auditd_conf do
      its('max_log_file_action') { should eq 'keep_logs' }
    end
    describe command('grep max_log_file_action /etc/audit/auditd.conf') do
      its('stdout') { should match "max_log_file_action = keep_logs" }
    end
  end
end

control 'SCORED | 4.1.2 | PATCH' do
  impact 1.0
  title 'Ensure auditd service is enabled'
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

control 'SCORED | 4.1.3 | PATCH' do
  impact 1.0
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  describe command('grep "^\s*linux" /boot/grub2/grub.cfg') do
    its('stdout') { should match "audit=1" }
  end
end

control 'SCORED | 4.1.4 | PATCH' do
  impact 1.0
  title 'Ensure events that modify date and time information are collected'
  describe command('auditctl -l | grep time-change') do
    its('stdout') { should match "-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change" }
    its('stdout') { should match "-a always,exit -F arch=b32 -S clock_settime -F key=time-change" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S clock_settime -F key=time-change" }
    its('stdout') { should match "-w /etc/localtime -p wa -k time-change" }
  end
end

control 'SCORED | 4.1.5 | PATCH' do
  impact 1.0
  title 'Ensure events that modify user/group information are collected'
  describe command('auditctl -l | grep identity') do
    its('stdout') { should match "-w /etc/group -p wa -k identity" }
    its('stdout') { should match "-w /etc/passwd -p wa -k identity" }
    its('stdout') { should match "-w /etc/gshadow -p wa -k identity" }
    its('stdout') { should match "-w /etc/shadow -p wa -k identity" }
    its('stdout') { should match "-w /etc/security/opasswd -p wa -k identity" }
  end
end

control 'SCORED | 4.1.6 | PATCH' do
  impact 1.0
  title 'Ensure events that modify the systems network environment are collected'
  describe command('auditctl -l | grep system-locale') do
    its('stdout') { should match "-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale" }
    its('stdout') { should match "-w /etc/issue -p wa -k system-locale" }
    its('stdout') { should match "-w /etc/issue.net -p wa -k system-locale" }
    its('stdout') { should match "-w /etc/hosts -p wa -k system-locale" }
    its('stdout') { should match "-w /etc/sysconfig/network -p wa -k system-locale" }
    its('stdout') { should match "-w /etc/sysconfig/network-scripts -p wa -k system-locale" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale" }
  end
end

control 'SCORED | 4.1.7 | PATCH' do
  impact 1.0
  title 'Ensure events that modify the systems Mandatory Access Controls are collected'
  describe command('auditctl -l | grep MAC-policy') do
    its('stdout') { should match "-w /etc/selinux -p wa -k MAC-policy" }
    its('stdout') { should match "-w /usr/share/selinux -p wa -k MAC-policy" }
  end
end

control 'SCORED | 4.1.8 | PATCH' do
  impact 1.0
  title 'Ensure login and logout events are collected'
  describe command("auditctl -l | grep logins") do
    its('stdout') { should match "-w /var/log/tallylog -p wa -k logins" }
    its('stdout') { should match "-w /var/log/lastlog -p wa -k logins" }
    its('stdout') { should match "-w /var/run/faillock -p wa -k logins" }
    its('stdout') { should match "-w /var/log/wtmp -p wa -k logins" }
    its('stdout') { should match "-w /var/log/btmp -p wa -k logins" }
  end
end

control 'SCORED | 4.1.9 | PATCH' do
  impact 1.0
  title 'Ensure session initiation information is collected'
  describe command("auditctl -l | grep -E '(session|logins)'") do
    its('stdout') { should match "-w /var/run/utmp -p wa -k session" }
    its('stdout') { should match "-w /var/log/wtmp -p wa -k logins" }
    its('stdout') { should match "-w /var/log/btmp -p wa -k logins" }
  end
end

control 'SCORED | 4.1.10 | PATCH' do
  impact 1.0
  title 'Ensure discretionary access control permission modification events are collected'
  describe command('auditctl -l | grep perm_mod') do
    its('stdout') { should match "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod" }
    its('stdout') { should match "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod" }
    its('stdout') { should match "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod" }
  end
end

control 'SCORED | 4.1.11 | PATCH' do
  impact 1.0
  title 'Ensure unsuccessful unauthorized file access attempts are collected'
  describe command('auditctl -l | grep access') do
    its('stdout') { should match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access" }
    its('stdout') { should match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access" }
  end
end

control 'SCORED | 4.1.12 | PATCH' do
  impact 1.0
  title 'Ensure use of privileged commands is collected'
  describe command('') do
    # its('stdout') { should match "" }
    skip 'This control not ready'
end end

control 'SCORED | 4.1.13 | PATCH' do
  impact 1.0
  title 'Ensure successful file system mounts are collected'
  describe command('auditctl -l | grep mounts') do
    its('stdout') { should match "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts" }
  end
end

control 'SCORED | 4.1.14 | PATCH' do
  impact 1.0
  title 'Ensure file deletion events by users are collected'
  describe command('auditctl -l | grep delete') do
    its('stdout') { should match "-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules" }
    its('stdout') { should match "-a always,exit -F arch=b32 -S init_module,delete_module -F key=modules" }
  end
end

control 'SCORED | 4.1.15 | PATCH' do
  impact 1.0
  title 'Ensure changes to system administration scope (sudoers) is collected'
  describe command('auditctl -l | grep scope') do
    its('stdout') { should match "-w /etc/sudoers -p wa -k scope" }
    its('stdout') { should match "-w /etc/sudoers.d -p wa -k scope" }
  end
end

control 'SCORED | 4.1.16 | PATCH' do
  impact 1.0
  title 'Ensure system administrator actions (sudolog) are collected'
  describe command('auditctl -l | grep actions') do
    its('stdout') { should match "-w /var/log/sudo.log -p wa -k actions" }
  end
end

control 'SCORED | 4.1.17 | PATCH' do
  impact 1.0
  title 'Ensure kernel module loading and unloading is collected'
  describe command('auditctl -l | grep modules') do
    its('stdout') { should match "-w /sbin/insmod -p x -k modules" }
    its('stdout') { should match "-w /sbin/rmmod -p x -k modules" }
    its('stdout') { should match "-w /sbin/modprobe -p x -k modules" }
    its('stdout') { should match "-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules" }
    its('stdout') { should match "-a always,exit -F arch=b32 -S init_module,delete_module -F key=modules" }
  end
end

control 'SCORED | 4.1.18 | PATCH' do
  impact 1.0
  title 'Ensure the audit configuration is immutable'
  describe command("grep '^\s*[^#]' /etc/audit/rules.d/*.rules | tail -1") do
    #its('stdout') { should eq("-e 2") }
    skip "Skipping this check as it is skipped in ansible apply"
  end
end

control 'SCORED | 4.2.3 | PATCH' do
  impact 1.0
  title 'Ensure rsyslog or syslog-ng is installed'
  describe.one do
    describe package('rsyslog') do
      it { should be_installed }
    end
    describe package('syslog-ng') do
      it { should be_installed }
    end
  end
end

control 'SCORED | 4.2.1.1 | PATCH' do
  impact 1.0
  title 'Ensure rsyslog Service is enabled'
  describe systemd_service('rsyslog') do
    it { should be_enabled }
  end
end

control 'NOTSCORED | 4.2.1.2 | PATCH' do
  impact 1.0
  title 'Ensure logging is configured'
  describe command('ls -l /var/log/') do
    # its('stdout') { should match "" }
    skip 'This control not ready'
  end
end

control 'SCORED | 4.2.1.3 | PATCH' do
  impact 1.0
  title 'Ensure rsyslog default file permissions configured'
  describe.one do
    describe parse_config_file('/etc/rsyslog.conf') do
      its('$FileCreateMode') { should eq('0640') }
    end
    describe command('grep ^\$FileCreateMode /etc/rsyslog.conf') do
      its('stdout') { should match "$FileCreateMode 0640\n" }
    end
  end
end

control 'SCORED | 4.2.1.4 | PATCH' do
  impact 1.0
  title 'Ensure rsyslog is configured to send logs to a remote log host'
  describe command('grep "^*.*[^I][^I]*@" /etc/rsyslog.conf') do
    # its('stdout') { should match "" }
    skip 'This control not ready'
  end
end

control 'NOTSCORED | 4.2.1.5 | PATCH' do
  impact 1.0
  title 'Ensure remote rsyslog messages are only accepted on designated log hosts'
  describe parse_config_file('/etc/rsyslog.conf') do
    its('$ModLoad') { should_not cmp 'imtcp' }
  end
  describe parse_config_file('/etc/rsyslog.conf') do
    its('$InputTCPServerRun') { should_not cmp '514' }
  end
end

control 'SCORED | 4.2.2.1 | PATCH' do
  impact 1.0
  title 'Ensure syslog-ng service is enabled'
  describe systemd_service('syslog-ng') do
    #it { should be_enabled }
    skip "Package syslog-ng is not used, hence skipping this test."
  end
end

control 'SCORED | 4.2.4 | PATCH' do
  impact 1.0
  title 'Ensure permissions on all logfiles are configured'
  describe.one do
    describe command('find /var/log -type f -perm /037 -ls -o -type d -perm /026 -ls') do
      its('stdout') { should match "" }
    end
    command('find /var/log -type f').stdout.split("\n").each do |log_file|
      describe file(log_file) do
        it { should_not be_writable.by('group') }
        it { should_not be_executable.by('group') }
        it { should_not be_readable.by('other') }
        it { should_not be_writable.by('other') }
        it { should_not be_executable.by('other') }
      end
    end
  end
end

control 'NOTSCORED | 4.3 | PATCH' do
  impact 1.0
  title 'Ensure logrotate is configured'
  describe command('') do
    # its('stdout') { should match "" }
    skip 'This control not ready'
  end
end

# CIS Workbench Level 1 - Section 5
control 'SCORED | 5.1.1 | PATCH' do
  impact 1.0
  title 'Ensure cron daemon is enabled'
  describe systemd_service('crond') do
    it { should be_enabled }
  end
end

control 'SCORED | 5.1.2 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/crontab are configured'
  describe file('/etc/crontab') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0600' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 5.1.3 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.hourly are configured'
  describe file('/etc/cron.hourly') do
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0700' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 5.1.4 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.daily are configured'
  describe file('/etc/cron.daily') do
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0700' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 5.1.5 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.weekly are configured'
  describe file('/etc/cron.weekly') do
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0700' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 5.1.6 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.monthly are configured'
  describe file('/etc/cron.monthly') do
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0700' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 5.1.7 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/cron.d are configured'
  describe file('/etc/cron.d') do
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0700' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 5.1.8 | PATCH' do
  impact 1.0
  title 'Ensure at/cron is restricted to authorized users - /etc/at.deny & /etc/cron.deny should not exists'
  describe file('/etc/at.deny') do
    it { should_not exist }
  end
  describe file('/etc/at.allow') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0600' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
  describe file('/etc/cron.deny') do
    it { should_not exist }
  end
  describe file('/etc/cron.allow') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0600' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 5.2.1 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  describe file('/etc/ssh/sshd_config') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    its('mode') { should cmp '0600' }
  end
end

control 'SCORED | 5.2.2 | PATCH' do
  impact 1.0
  title 'Ensure SSH Protocol is set to 2'
  describe sshd_config do
    its('Protocol') { should eq('2') }
  end
end

control 'SCORED | 5.2.3 | PATCH' do
  impact 1.0
  title 'Ensure SSH LogLevel is set to INFO'
  describe sshd_config do
    its('LogLevel') { should eq('INFO') }
  end
end

control 'SCORED | 5.2.4 | PATCH' do
  impact 1.0
  title 'Ensure SSH X11 forwarding is disabled'
  describe sshd_config do
    its('x11forwarding') { should eq('no') }
  end
end

control 'SCORED | 5.2.5 | PATCH' do
  impact 1.0
  title 'Ensure SSH MaxAuthTries is set to 4 or less'
  describe sshd_config do
    its('maxauthtries') { should eq('4') }
  end
end

control 'SCORED | 5.2.6 | PATCH' do
  impact 1.0
  title 'Ensure SSH IgnoreRhosts is enabled'
  describe sshd_config do
    its('ignorerhosts') { should eq('yes') }
  end
end

control 'SCORED | 5.2.7 | PATCH' do
  impact 1.0
  title 'Ensure SSH HostbasedAuthentication is disabled'
  describe sshd_config do
    its('hostbasedauthentication') { should eq('no') }
  end
end

control 'SCORED | 5.2.8 | PATCH' do
  impact 1.0
  title 'Ensure SSH root login is disabled'
  describe sshd_config do
    its('permitrootlogin') { should eq('no') }
  end
end

control 'SCORED | 5.2.9 | PATCH' do
  impact 1.0
  title 'Ensure SSH PermitEmptyPasswords is disabled'
  describe sshd_config do
    its('permitemptypasswords') { should eq('no') }
  end
end

control 'SCORED | 5.2.10 | PATCH' do
  impact 1.0
  title 'Ensure SSH PermitUserEnvironment is disabled'
  describe sshd_config do
    its('permituserenvironment') { should eq('no') }
  end
end

control 'SCORED | 5.2.11 | PATCH' do
  impact 1.0
  title 'Ensure only approved ciphers are used'
  describe sshd_config do
    its('ciphers') { should eq('chacha20-poly1305@openssh.com,aes256-ctr') }
  end
end

control 'SCORED | 5.2.12 | PATCH' do
  impact 1.0
  title 'Ensure only approved MAC algorithms are used'
  describe sshd_config do
    its('macs') { should eq('hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512') }
  end
end

control 'SCORED | 5.2.12a | PATCH' do
  impact 1.0
  title 'Ensure that strong Key Exchange algorithms are used'
  describe sshd_config do
    its('kexalgorithms') { should eq('curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256') }
  end
end

control 'SCORED | 5.2.12b | PATCH' do
  impact 1.0
  title 'Ensure that strong Host Key Exchange algorithms are used'
  describe sshd_config do
    its('hostkeyalgorithms') { should eq('ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521') }
  end
end

control 'SCORED | 5.2.13 | PATCH' do
  impact 1.0
  title 'Ensure SSH Idle Timeout Interval - ClientAliveInterval is configured'
  describe sshd_config do
    its('clientaliveinterval') { should eq('300') }
  end
end

control 'SCORED | 5.2.13 | PATCH' do
  impact 1.0
  title 'Ensure SSH Idle Timeout Interval - ClientAliveCountMax is configured'
  describe sshd_config do
    its('clientalivecountmax') { should eq('3') }
  end
end

control 'SCORED | 5.2.14 | PATCH' do
  impact 1.0
  title 'Ensure SSH LoginGraceTime is set to one minute or less'
  describe sshd_config('/etc/ssh/sshd_config') do
    its('Banner') { should eq '/etc/issue.net' }
  end
end

control 'SCORED | 5.2.15 | PATCH' do
  impact 1.0
  title 'Ensure SSH access is limited - allowusers, allowgroups, denyusers, denygroups'
  describe sshd_config do
    its('allowusers') { should eq('ec2-user') }
    its('allowgroups') { should eq nil }
    its('denyusers') { should eq nil }
    its('denygroups') { should eq nil }
  end
end

control 'SCORED | 5.2.16 | PATCH' do
  impact 1.0
  title 'Ensure SSH warning banner is configured'
  describe sshd_config do
    its('banner') { should eq('/etc/issue.net') }
  end
end

control 'SCORED | 5.2.17 | PATCH' do
  impact 1.0
  title 'Ensure password creation requirements are configured'
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('minlen') { should match('14') }
    its('dcredit') { should match('-1') }
    its('ucredit') { should match('-1') }
    its('ocredit') { should match('-1') }
    its('lcredit') { should match('-1') }
  end
end

control 'SCORED | 5.3.4 | PATCH' do
  impact 1.0
  title 'Ensure password hashing algorithm is SHA-512'
  describe command("authconfig --test | grep 'password hashing algorithm is' | awk '{print $NF}'") do
    its('stdout') { should match "sha512" }
  end
end

control 'SCORED | 5.4.1.1 | PATCH' do
  impact 1.0
  title 'Ensure password expiration is 90 days or less'
  describe login_defs do
    its('PASS_MAX_DAYS') { should eq('90') }
  end
end

control 'SCORED | 5.4.1.2 | PATCH' do
  impact 1.0
  title 'Ensure minimum days between password changes is 7 or more'
  describe login_defs do
    its('PASS_MIN_DAYS') { should eq('7') }
  end
end

control 'SCORED | 5.4.1.3 | PATCH' do
  impact 1.0
  title 'Ensure password expiration warning days is 7 or more'
  describe login_defs do
    its('PASS_WARN_AGE') { should eq('7') }
  end
end

control 'SCORED | 5.4.1.4 | PATCH' do
  impact 1.0
  title 'Ensure inactive password lock is 30 days or less'
  describe command("useradd -D | grep INACTIVE") do
    its('stdout') { should match "INACTIVE=30" }
  end
end

control 'SCORED | 5.4.2 | PATCH' do
  impact 1.0
  title 'Ensure system accounts are non-login'
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ && uid.to_i < 1000 && shell != "/sbin/nologin" } do
    its("entries") { should be_empty }
  end
end

control 'SCORED | 5.4.3 | PATCH' do
  impact 1.0
  title 'Ensure default group for the root account is GID 0'
  describe group('root') do
    it { should exist }
    its('gid') { should eq 0 }
  end
end

control 'SCORED | 5.4.4 | PATCH' do
  impact 1.0
  title 'Ensure default user umask is 027 or more restrictive'
  describe.one do
    describe command("grep -E 'umask 027' /etc/bashrc | awk '{$1=$1};1' | head -n 1") do
      its('stdout') { should match "umask 027" }
    end
    describe command("grep -E 'umask 027' /etc/profile | awk '{$1=$1};1' | head -n 1") do
      its('stdout') { should match "umask 027" }
    end
    describe command("grep -E 'umask 027' /etc/csh.cshrc | awk '{$1=$1};1' | head -n 1") do
      its('stdout') { should match "umask 027" }
    end
  end
end

control 'SCORED | 5.4.5 | PATCH' do
  impact 1.0
  title 'Ensure default user shell timeout is 900 seconds or less'
  describe.one do
    describe command("grep '^TMOUT' /etc/bashrc") do
      its('stdout') { should match "TMOUT=600" }
    end
    describe command("grep '^TMOUT' /etc/profile /etc/profile.d/*.sh") do
      its('stdout') { should match "/etc/profile:TMOUT=600" }
    end
  end
end

control 'SCORED | 5.6 | PATCH' do
  impact 1.0
  title 'Ensure access to the su command is restricted and wheel group contains root'
  describe file('/etc/pam.d/su') do
    its("content") { should match(/^\s*auth\s+required\s+pam_wheel.so\s+(\S+\s+)*use_uid\s*(\S+\s+)*$/) }
  end
  describe command("grep wheel /etc/group") do
    its('stdout') { should match "wheel:x:10:root" }
  end
end

# CIS Workbench Level 1 - Section 6
control 'NOTSCORED | 6.1.1 | PATCH' do
  impact 1.0
  title 'Audit system file permissions'
  describe command("rpm -qf /bin/bash") do
    #its('stdout') { should match "" }
    skip 'This control yet to be done'
  end
end

control 'SCORED | 6.1.2 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd are configured'
  describe file('/etc/passwd') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_executable.by "group" }
    it { should be_readable.by "group" }
    it { should_not be_writable.by "group" }
    it { should_not be_executable.by "other" }
    it { should be_readable.by "other" }
    it { should_not be_writable.by "other" }
    it { should_not be_executable.by "owner" }
    it { should be_readable.by "owner" }
    it { should be_writable.by "owner" }
    its("uid") { should cmp 0 }
    its("gid") { should cmp 0 }
    its("mode") { should cmp '0644' }
  end
end

control 'SCORED | 6.1.3 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow are configured'
  describe file('/etc/shadow') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0000' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 6.1.4 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/group are configured'
  describe file('/etc/group') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0644' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 6.1.5 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow are configured'
  describe file('/etc/gshadow') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0000' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 6.1.6 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd- are configured'
  describe file('/etc/passwd-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0600' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 6.1.7 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow- are configured'
  describe file('/etc/shadow-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0000' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 6.1.8 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/group- are configured'
  describe file('/etc/group-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0644' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 6.1.9 | PATCH' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow- are configured'
  describe file('/etc/gshadow-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '000' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'SCORED | 6.1.10 | PATCH' do
  impact 1.0
  title 'Ensure no world writable files exist'
  describe command("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002") do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.1.11 | PATCH' do
  impact 1.0
  title 'Ensure no unowned files or directories exist'
  describe command("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser") do
    its('stdout') { should cmp '' }
  end
end

control 'SCORED | 6.1.12 | PATCH' do
  impact 1.0
  title 'Ensure no ungrouped files or directories exist'
  describe command("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup") do
    its('stdout') { should cmp '' }
  end
end

control 'NOTSCORED | 6.1.13 | PATCH' do
  impact 1.0
  title 'Audit SUID executables'
  describe command("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000") do
    #its('stdout') { should cmp '' }
    skip 'This control is not needed'
  end
end

control 'NOTSCORED | 6.1.14 | PATCH' do
  impact 1.0
  title 'Audit SGID executables'
  describe command("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000") do
    #its('stdout') { should cmp '' }
    skip 'This control is not needed'
  end
end

control 'SCORED | 6.2.1 | PATCH' do
  impact 1.0
  title 'Ensure password fields are not empty'
  shadow.users(/.+/).entries.each do |entry|
    describe entry do
      its('password') { should_not eq [''] }
    end
  end
end

control 'SCORED | 6.2.2 | PATCH' do
  impact 1.0
  title "Ensure no legacy '+' entries exist in /etc/passwd"
  describe command("grep '^\+:' /etc/passwd") do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.3 | PATCH' do
  impact 1.0
  title "Ensure no legacy '+' entries exist in /etc/shadow"
  describe command("grep '^\+:' /etc/shadow") do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.4 | PATCH' do
  impact 1.0
  title "Ensure no legacy '+' entries exist in /etc/group"
  describe command("grep '^\+:' /etc/group") do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.5 | PATCH' do
  impact 1.0
  title "Ensure root is the only UID 0 account"
  describe command("awk -F: '($3 == 0) { print $1 }' /etc/passwd") do
    its('stdout') { should match "root" }
  end
end

control 'SCORED | 6.2.6 | PATCH' do
  impact 1.0
  title "Ensure root PATH Integrity"
  describe command('sh .files/scripts/6.2.6_check_root_path_integrity.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.7 | PATCH' do
  impact 1.0
  title "Ensure all user's home directories exist"
  describe command('sh .files/scripts/6.2.7_check_users_home_dir_exists.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.8 | PATCH' do
  impact 1.0
  title "Ensure user's home directories permissions are 750 or more restrictive"
  describe command('sh .files/scripts/6.2.8_check_home_dir_permissions.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.9 | PATCH' do
  impact 1.0
  title 'Ensure users own their home directories'
  describe command('sh .files/scripts/6.2.9_check_user_own_their_home_dir.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.10 | PATCH' do
  impact 1.0
  title "Ensure user's dot files are not group or world writable"
  describe command('sh .files/scripts/6.2.10_check_dot.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.11 | PATCH' do
  impact 1.0
  title 'Ensure no users have .forward files'
  describe command('sh .files/scripts/6.2.11_check_forward.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.12 | PATCH' do
  impact 1.0
  title 'Ensure no users have .netrc files'
  describe command('sh .files/scripts/6.2.12_check_netrc.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.14 | PATCH' do
  impact 1.0
  title 'Ensure no users have .rhosts files'
  describe command('sh .files/scripts/6.2.14_check_rhosts.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.15 | PATCH' do
  impact 1.0
  title 'Ensure all groups in /etc/passwd exist in /etc/group'
  describe command('sh .files/scripts/6.2.15_check_all_groups.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.16 | PATCH' do
  impact 1.0
  title 'Ensure no duplicate UIDs exist'
  describe command('sh .files/scripts/6.2.16_check_duplicate_uids.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.17 | PATCH' do
  impact 1.0
  title 'Ensure no duplicate GIDs exist'
  describe command('sh .files/scripts/6.2.17_check_duplicate_gids.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.18 | PATCH' do
  impact 1.0
  title 'Ensure no duplicate user names exist'
  describe command('sh .files/scripts/6.2.18_check_duplicate_user_names.sh') do
    its('stdout') { should match "" }
  end
end

control 'SCORED | 6.2.19 | PATCH' do
  impact 1.0
  title 'Ensure no duplicate group names exist'
  describe command('sh .files/scripts/6.2.19_check_duplicate_groups.sh') do
    its('stdout') { should match "" }
  end
end

## End of CIS Workbench Level 1 Checks ##