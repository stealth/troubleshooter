##                     troubleshooter

####          The revenge of _GingerBreak_

__Abstract:__ This paper demonstrates vulnerabilities within the
SELinux framework as well as shortcomings in the type enforcement setup.
I will show how to deconstruct a SELinux setup with some simple 80's style
exploit techniques. While reading this paper, I recommend listening
to [this music from the year of morrisworm.](https://www.youtube.com/watch?v=ufERJEdcfAY)

##### Introduction

When in 2012 the SELinux developers analyzed the behaivior of an exploit
that was not designed to run on a SELinux system [at page 32 of these slides](http://selinuxproject.org/~seandroid/slides/LinuxConNA2012-SEAndroid.pdf) - it
triggered  a review-selector for SELinux and I put it to the list of my audit
targets. Not surprisingly, _GingerBreak_ lost that "competition", just because
it was not made for it. Using my QUANTUM AUDIT techniques I was now able to have
a deeper look into SELinux itself to see whether the claims that were made
really hold.


##### The AVC subsystem

SELinux is basically split into two parts. The kernel part, which mostly
consists of the Access Vector Cache (AVC) logic, and a userspace part which
I will call the SELinux framework. The framework consists of a lot of Python
scripts running as root and/or as a DBUS service. The AVC itself basically
decides whether a permission is granted or not, based on the typing and
transitioning rules from the policy.

When the AVC denies access, it used to send a netlink message from the kernel
to the audit subsystem which looks like this:

```
type=AVC msg=audit(1427104951.889:423): avc:  denied  { open } for  pid=2521
comm="openvpn" path=2F74[...]27 dev="tmpfs" ino=31315
scontext=system_u:system_r:openvpn_t:s0
tcontext=unconfined_u:object_r:user_tmp_t:s0 tclass=file permissive=0
```
within a single line. It basically tells the admin that _openvpn_, running
in the *openvpn_t* domain, was denied access to a file object with type
*user_tmp_t*. The pathname of the object in question is encoded as hex string
for a reason. This logging makes sense in order to maintain the system.

The audit subsystem can be be further configured with plugins to handle such
messages. For example on a Fedora 21 system there is a plugin that further
mangles such messages via _sedispatch_ to the _setroubleshoot_ DBUS service.
Since everything in a targeted policy is safe due to type enforcement MAC
(which we will break later), all this runs as root of course.

##### Where is my mind?

Now lets have a look on how this _setroubleshoot_ DBUS service, running as
root (although in its SELinux domain sandbox), handles this untrusted pathname
input originating from the AVC deny message:

```Python
def get_rpm_nvr_by_file_path_temporary(name):
    if name is None or not os.path.exists(name):
        return None

    nvr = None
    try:
        import commands
        rc, output = commands.getstatusoutput("rpm -qf '%s'" % name)
        if rc == 0:
            nvr = output
    except:
        syslog.syslog(syslog.LOG_ERR, "failed to retrieve rpm info for %s" % name)
    return nvr
```

The _setroubleshootd_ daemon which runs as root, activated by its DBUS
activation file when _sedispatch_ was forwarding its AVC denial message,
straight passes the pathname to a shell without further sanitization. This
directly pops us in a rootshell running in the *setroubleshootd_t* domain.
Bad luck for us, this domain is not allowed to dump the shadow file. The
framework which is meant to protect you by means of a MAC system, just
donated a __uid 0__ shell to the attacker.

The next chapter will show how this particular MAC setup can't even hold
what it promised to be their stronghold: Once (in the unlikely case) an
attacker successfully exploited a process, he is caged in its unprivileged
domain.


##### Containers dont contain.

And so don't domains. I really love that deep sentence that was philosophically
spoken in response to my docker exploit which demonstrated a breakout of the
docker container. Programmers are the better philosophers.

By looking at the policy rules with regard to the *setroubleshootd_t* domain,
we quickly find that it is allowed to *create* and *setattr* file objects within
its own directory. This comes with little surprise, but it allows us to mount
the well known __Vichy-attack__ against sandboxed systems where two domains
collaborate. That is, the command is constructed as follows:

```
cd var;cd lib;cd setroubleshoot;cat $SHELL > sh;chmod 04755 sh
```
Its necessary to avoid the `/` character because we are passing
along a filename and it makes things easier since we dont need
to create sub directories. This command, when executed from within
the *setroubleshootd_t* domain, will leave a suid shell in place
for the discretionary execution by the attacker who already runs
his shell in the *unconfined_t* domain.

![Voila!](https://github.com/stealth/troubleshooter/blob/master/troubleshooter.jpg)

A demo exploit using _NetworkManager's_ openvpn plugin as an attack vector is
included in this git. Dont get fooled: There exist many other
attack vectors (not just _NetworkManager's_ integrated wifi setup in case
the openvpn plugin is not available), some of
them might work remotely. All an attacker needs to do is to trick a confined
domain to access one of his files. If **polkit** has rules to just allow
active or console sessions to access the attack vector, that is not an
obstacle either: just put it to the target user's *.bashrc* to execute
it on the attacker's behalf.

##### Conclusion

I just demonstrated an exploit against SELinux itself (not an exploit
against some buggy 3rd party suid binary which it claims to mitigate)
with simplest exploit math. I further outlined that the claims of confinement
were wrong.
No kernel exploits such as [these](http://grsecurity.net/~spender/exploits/) were required. Kernel security is a different topic, best discussed with spender.

##### Epilogue

You might be surprised to hear that despite this writeup I am
still convinced that MAC systems (and the SELinux type enforcement
in particular) are still very valuable. At least the SELinux core (the
kernel part and some of the libraries) are of good code quality and
type enforcement has been well researched. If you play a little bit
around with it you immediately see its value and get to know that
it has its beauty. However, type enforcement does not allow to switch
off the brain and to frame around a lot of crap that eventually just throws
away what the MAC system initially bought you.
In fact, SELinux has silently become the largest installation base of a MAC
system by the SEAndroid rollout since __KitKat__, without major problems.

Let me stress that I dont point at people making bugs/mistakes. I certainly
have enough stupid bugs in my own code. However, projects making claims
and presentations based on wrong assumptions deserve a deeper look. In
particular if made by organizations that play the interdiction game on
the backflip of the coin.
I just felt it was necessary to demonstrate how it would look like when I
target a MAC system and that mitigation of exploits _not_ targeting type
enforcement has to be put in context since today.

##### Donations

If you like __troubleshooter__, please consider donating at the
donation button [here](https://c-skills.blogspot.com)
or to the [SELinux rescue funds](https://supporters.eff.org/donate) with
subject _troubleshooter_.
Thanks in advance. I am doing this work as part of my _Dr.xSports._
thesis by grant No. 743c13377350.

##### References

* [SELinux project](http://selinuxproject.org/page/Main_Page)
* [setroubleshoot](https://fedorahosted.org/setroubleshoot/)
* [setroubleshoot git](https://git.fedorahosted.org/git/setroubleshoot.git)
* [Mandatory Access Control (MAC)](http://en.wikipedia.org/wiki/Mandatory_access_control)
* [grsecurity](https://grsecurity.net)
* [docker exploit](http://stealth.openwall.net/xSports/shocker.c)
* [KitKat + SEAndroid](https://software.intel.com/en-us/android/articles/android-security-customization-with-seandroid)

