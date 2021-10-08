# pscan

`pscan` is a TCP port scanner, which can be used to scan hosts/networks for
open TCP ports. Results can be printed in human readable or JSON format.

## Building

`pscan` is written with [rust](http://www.rust-lang.org/). If you have rust toolchain installed
you can compile it with `cargo build --release`. Currently Linux and Mac OS are
supported platforms.

## Usage

Use `pscan --help` to get help for command line parameters:

```
TCP port scanner 0.1.0

USAGE:
    pscan [FLAGS] [OPTIONS]

FLAGS:
    -h, --help              Prints help information
    -B, --read-banner       Try to read up to read-banner-size bytes (with read-banner-timeout) when connection is
                            established
    -R, --retry-on-error    Retry scan a few times on (possible transient) network error
    -V, --version           Prints version information
    -v, --verbose           Verbose output

OPTIONS:
    -b, --concurrent-scans <concurrent-scans>          Number of concurrent scans to run [default: 100]
    -C, --config <config>                              Read configuration from given JSON file
    -e, --exclude <exclude>                            Comma -separated list of addresses to exclude from scanning
    -j, --json <json>                                  Write output as JSON into given file, - to write to stdout
    -p, --ports <ports>                                Ports to scan [default: 1-100]
        --read-banner-size <read-banner-size>
            Maximum number of bytes to read when reading banner from open port [default: 256]

        --read-banner-timeout <read-banner-timeout>
            Timeout in ms to wait for when reading banner from open port [default: 1000]

    -t, --target <target>
            Address(es) of the host(s) to scan, IP addresses, or CIDRs separated by comma

    -T, --timeout <timeout>
            Timeout in ms to wait for response before determening port as closed/firewalled [default: 1000]

    -r, --try-count <try-count>
            Number of times to try a port which receives no response (including the initial try) [default: 2]
```

To scan hosts or networks, give the addresses of targets with `--target` command line option. The targets should be comma -separated list of
IP addresses or networks in CIRD notataion (address/mask). Single hosts can be excluded from scan using `--exclude` options. Ports to scan can be defined with `--ports` option. The `--timeout` option specifies how long to wait (in ms) for connection to establish before
marking the port as filtered.

To scan all ports from "192.168.1.0/24" network and hosts "10.0.0.1" and "10.0.0.2" except host "192.168.1.100", run `pscan` with
```
pscan --target 192.168.1.0/24,10.0.0.1,10.0.0.2 --exclude 192.168.1.100 --ports 1-65535
```

Number of concurrent scans, that is how many ports are scanned at once, can be controlled with `--concurrent-scans` option. Note that
increasing this number above the "max open files" ulimit will cause error, this limit can be increased with `ulimit -n` command.

If `--read-banner` flag is set, `pcsan` will try to read data from open ports and will show any data received once scan is complete. The
`--read-banner-size` and `--read-banner-timeout` options can be used to define the maximum number of bytes to read and how long to wait for
data.

By default, ports for which no response is received are retried once before marking them as filtered. With `--try-count` option the number of
times connection is tried can be changed.

### Configuration file

The configuration options can also be given in JSON -formated confguration file. To read the configuration file use `--config` command line
option. The configuration file should contain JSON object whose fields are command line options:
```json
{
    "target": "192.168.1.0/24, 10.0.0.1, 10.0.0.2",
    "exclude": "192.168.1.100",
    "ports": "22,80,8080,443,8443,9000-9005",
    "read-banner": true
}
```

Options set on command line will overwrite options set on configuration file. Default values
for command line options are used for options not specified on configuration file.

## Ouput

By default `pscan` will print summary on command line after a scan has been completed:
```
jtt@jimmy:~/pscan$ ./pscan -t 192.168.1.0/24 -p 1-65535 -b 1000 -r 2 -B
Scan complete:
 192.168.1.1 is Up
        5 Open Ports: 80 22 443 10001 53
        65530 ports closed and 0 filtered (delays: min 0ms, max 133ms)

192.168.1.202 is Up
        10 Open Ports: 22 5514 3000 8843 8080 8081 6789 8443 8880 8086
        65525 ports closed and 0 filtered (delays: min 0ms, max 10ms)
         Banners received from open ports:
                Port: 22 "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"

192.168.1.241 is Up
        4 Open Ports: 1443 1843 1400 1410
        64271 ports closed and 1260 filtered (delays: min 1ms, max 355ms)

65535 ports on 256 hosts scanned, 2 hosts did not have open ports, 241 hosts reported down by OS
```

If `--verbose` command line option is given, `pscan` will print information as
hosts are scanned and summary after scan is completed.

The output of `pscan` can change from time to time and is not meant to be parsed by other programs.
The JSON output is more stable and can be used to parse the results by other programs.


### JSON Ouput

With `--json` commmand line option results are printed in JSON format to a file with a given name.
If `-` is given as file name, the JSON data is written to stdout.

The results are written as single JSON object followed by newline. When parsing data, well formed
JSON object should have been received after a line has been read.

JSON output is as follows:
```json
{
  "message": "scan_complete",
  "number_of_hosts": 256,
  "number_of_ports": 65535,
  "results": [
    {
      "host": "192.168.1.202",
      "open_ports": [
        22,
        5514,
        3000,
        6789,
        8080,
        8081,
        8843,
        8443,
        48668,
        46122,
        42762,
        8086,
        8880
      ],
      "closed": 65522,
      "filtered": 0,
      "banners": {
        "22": "U1NILTIuMC1PcGVuU1NIXzcuOXAxIERlYmlhbi0xMCtkZWIxMHUyDQo="
      }
    },
    {
      "host": "192.168.1.241",
      "open_ports": [
        1443,
        1843,
        1400,
        1410
      ],
      "closed": 65293,
      "filtered": 238,
      "banners": {}
    },
    {
      "host": "192.168.1.1",
      "open_ports": [
        80,
        22,
        443,
        10001,
        53
      ],
      "closed": 65530,
      "filtered": 0,
      "banners": {}
    },
  ]
}

```
| Element | Value |
| -- | --|
|message| "type" for the data, currently "`scan_complete`" is the only one supported |
|numer_of_hosts| Number of hosts scanned|
|number_of_ports| Number of ports scanned on each host|
|results| Array of objects, each object containing result for host with at least one open port |
|result:host| IP Address of scanned host |
|result:open_ports| Array containing open port numbers |
|result:closed| Number of closed (for which the remote end replied) ports |
|result:filtered| Number of filtered (for which we did not receive reply) ports |
|result:banners| Object containing port number a "key" and data received base64 encoded as value |







