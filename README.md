Nagios-to-Alerta Gateway
========================

[![Build Status](https://travis-ci.org/alerta/nagios-alerta.png)](https://travis-ci.org/alerta/nagios-alerta)

Consolidate Nagios alerts from across multiple sites into a single "at-a-glance" console. Nagios 3 and Nagios 4 are now supported.

Transform this ...

![nagios](/docs/images/nagios3-v3.png?raw=true)

Into this ...

![alerta](/docs/images/nagios3-alerta-v3.png?raw=true)

System Requirements
------------

You'll need the following system packages to Install nagios-alerta:

In RedHat/CentOS/Fedora:
```
yum install -y git curl gcc make libcurl-devel
```

In Debian/Ubuntu:
```
apt-get install -y git curl gcc make libcurl-dev
```

Installation (Nagios 3)
------------

    $ git clone https://github.com/alerta/nagios-alerta.git
    $ cd nagios-alerta
    $ make
    $ sudo make install
    $ sudo service nagios restart

Installation (Nagios 4)
------------

    $ git clone https://github.com/alerta/nagios-alerta.git
    $ cd nagios-alerta
    $ make nagios4
    $ sudo make install
    $ sudo service nagios restart

Alerts
------

To forward host and service check results to Alerta, modify `/etc/nagios/nagios.cfg` as follows:
```
broker_module=/usr/lib/nagios/alerta-neb.o http://localhost:8080
```

To specify the environment name:
```
broker_module=/usr/lib/nagios/alerta-neb.o http://localhost:8080 env=ENV_NAME_HERE
```

To provide the API key if authentication is enabled on the alerta server:
```
broker_module=/usr/lib/nagios/alerta-neb.o http://localhost:8080 key=INSERT_API_KEY_HERE
```

To send alerts only for specific hosts (file must contains list of hosts separated by newline), default no filter:
```
broker_module=/usr/lib/nagios/alerta-neb.o http://localhost:8080 hosts=/path/to/host.txt
```

To filter alerts via the function check_if_alert (for now do not send alerts if acknowledged, flapping or if state is ok and previous state was ok), default no filter:
```
broker_module=/usr/lib/nagios/alerta-neb.o http://localhost:8080 filter=1
```

And to enable debug mode:
```
broker_module=/usr/lib/nagios/alerta-neb.o http://localhost:8080 debug=1
```

Heartbeats
----------

To configure the Nagios server to send regular heartbeats to Alerta to ensure that Nagios and the event broker are still forwarding alerts configure a dummy service check as follows:

1. Define a heartbeat command and add it to `/etc/nagios/commands.cfg`:
```
define command{
        command_name    check_heartbeat
        command_line    /usr/lib/nagios/plugins/check_dummy 0
}
```

2. Define a hostgroup for the Nagios servers that have the Alerta event broker installed and add it to `/etc/nagios3/conf.d/hostgroups_nagios2.cfg`:
```
define hostgroup {
        hostgroup_name  nagios-servers
                alias           Nagios servers
                members         localhost
}
```

3. Define a Heartbeat service check to execute every minute and add it to `/etc/nagios/conf.d/services_nagios2.cfg`:
```
define service {
        hostgroup_name                  nagios-servers
        service_description             Heartbeat
        check_command                   check_heartbeat
        use                             generic-service
        notification_interval           0 ; set > 0 if you want to be renotified
        normal_check_interval           1
}
```

License
-------

Copyright (c) 2013 Nick Satterly. Available under the MIT License.
