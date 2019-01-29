# probeguard
[ProbeGuard: Mitigating Probing Attacks Through Reactive Program Transformations [ASPLOS'19]](https://www.vusec.net/download/?t=papers/probeguard_asplos19.pdf)

Many modern defenses against code reuse rely on hiding sensitive data such as shadow stacks in a huge memory address space. While much more efficient than traditional integritybased defenses, these solutions are vulnerable to probing attacks which quickly locate the hidden data and compromise security. This has led researchers to question the value of information hiding in real-world software security. Instead, we argue that such a limitation is _not_ fundamental and that information hiding and integrity-based defenses are two extremes of a continuous spectrum of solutions.

We propose __ProbeGuard__, that automatically balances performance and security by deploying an existing information hiding based baseline defense and then incrementally moving to more powerful integrity-based defenses by hotpatching when probing attacks occur. ProbeGuard is efficient, provides strong security, and gracefully trades off performance upon encountering more probing primitives.

We will present [this paper](https://www.vusec.net/download/?t=papers/probeguard_asplos19.pdf) at [ASPLOS'19](https://asplos-conference.org/).

### Source code

We will publish the source code here, during the conference in April 2019.
