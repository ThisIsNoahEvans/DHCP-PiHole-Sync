# DHCP-PiHole-Sync

> **TL;DR:** I needed a way to block YouTube from kids on the home network entirely, regardless of the device they were using, whilst still allowing adults to watch YouTube when required.

By syncing with DHCP static leases, I don't have to worry about updating multiple systems to identify clients.

**My Pi-hole has two groups:**
- the default group (ID `0`) that has YouTube-blocking regexes applied
    - All new clients are added to this group and are unable to access YouTube.
    - This includes synced DHCP clients, and other clients Pi-hole has seen - even if they have not been explicitly assigned a group.
    - Therefore, new devices on the network are automatically blocked. 
- the "Allow YouTube" group (ID `1`) that does not have these regexes applied.

I make use of a Telegram bot to control YouTube access. I can send `/getclients` to receive an up-to-date list of all configured Pi-hole clients, and select a client to enable or disable YouTube access (by switching the groups).

When switching groups, any other groups (i.e. ad-blocking groups) are ignored and your own configuration is preserved.

This means that I can enable YouTube on a TV for example, for only the time that I am watching it - ensuring that kids still can't access it on another device or after I've finished watching and re-disabled it!

> **Note:** This is only DNS-level blocking. You should use a firewall block all other outgoing traffic on port 53 to ensure devices cannot use their own DNS servers, circumventing this. Smart TVs and streaming devices are prone to this - Google/Android TV in particular likes to ignore DNS servers obtained over DHCP.

## Usage
Change the appropriate parameters in the `main.go` file, build it, and run it as a system service.

For now I won't be providing more detailed instructions as I doubt many people will actually be running this.

It might break through Pi-hole updates as it replicates the web interface requests, rather than using the built-in API.

I wrote the code of an evening so it's not exceptionally well-written, but it seems to work...