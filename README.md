Setting up infrastructure for a Red Team engagement can be time consuming and difficult.  [Jeff Dimmock](https://twitter.com/bluscreenofjeff) and [Steve Borosh](https://twitter.com/424f424f) have done a lot of work to make this process easier and more transparent.  They gave a [great presentation](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure).  that went over the fundamentals of setting up good Red Team nfrastructure. As part of this effort they released a [wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki).

One of the most interesting bits of tradecraft released in this talk and on [Jeff's blog](https://bluescreenofjeff.com/tags#mod_rewrite) is their very creative use of apache2’s mod_rewrite functionality. Mod_Rewrite is very powerful for a few reasons:

1. It can be used to hide the true location of your Teamserver
2. It can be used to evade detection from Incident Response
3. It can be used to redirect mobile users away from a payload to a spoofed login portal, to capture credentials
4. It can be used to block specific ip addresses from your teamserver, to aid in IR evasion
5. It can be used to only allow your Malleable C2 traffic to the Teamserver

In a Red Team engagement, there are often multiple teamservers, and multiple redirectors in front of each teamserver. In the event that a defender identifies and blocks one of the redirectors, they should be easy to recreate. However, manually setting up mod_rewrite ruleset for each redirector can be very difficult and time consuming. To make this easier, I automated some of the setup process and tried to include as much functionality as possible.

For a more detailed description of the tool and how to use it please refer to this [Blog Post](https://blog.inspired-sec.com/archive/2017/04/17/Mod-Rewrite-Automatic-Setup.html)