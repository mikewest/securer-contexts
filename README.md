# Secur_er_ Contexts

Mike West, Feb 2020 (©2020, Google)

## A Problem

In 2015, we worked together to define a minimum bar for a websites' security. At the time, the
threats we were most concerned about were wrapped up in the blunting the capabilities of active and
passive network attackers. To that end, we defined a "[secure context][secure-context]" that
enforced security at the transport layer by ensuring that a given document and its ancestors were
securely delivered. We've very successfully parlayed that definition into
[`[SecureContext]`][secure-context-idl] requirements for a broad swath of important APIs, ensuring
that they're available only when they're safely out of the hands of everyone on the network between
the user and that site.

[secure-context]: https://www.w3.org/TR/secure-contexts/
[secure-context-idl]: https://heycam.github.io/webidl/#SecureContext

Focusing the threat model on the transport layer made a good deal of sense several years ago, while
we were in the midst of a large-scale migration from plaintext HTTP to encrypted HTTPS. That
migration has been wildly successful, with [the vast majority of page views and time spent][transparency]
on sites delivered securely. 

[transparency]: https://transparencyreport.google.com/https/overview?hl=en

Today, it seems clear that encryption is no longer our primary focus. While we can't quite declare
victory, encryption has become something we can simply assume for modern applications, rather than
something we need to actively advocate. It seems reasonable, then, to step back and revisit our
conception of what makes a site secure-enough, with an eye toward the next set of things that we'd
like web developers to begin doing in the service of protecting their users and themselves.

## A Proposal

Secure Contexts' threat model should extend beyond encrypting the transport layer, and bring
attention to application layer threats that rely on either injection or insufficient isolation.
Concretely, the model ought to include attackers who can:

1. Passively observe network traffic flows on the one hand; or actively modify, block, or replay
   traffic flows on the other. The risks these attackers pose is well-understood, and forms the
   core of the existing Secure Context restrictions.

2. Cause a server to "reflect" unexpected content directly into the body of any given response, or
   manipulate the inputs to client-side code (DOM APIs and otherwise), potentially leading to
   unexpected script execution.

3. Obtain references to a victim's window, which provides a `postMessage()` channel, and insight
   into the victim's state (via `window.frames` and friends).

4. Include a victim's resources in an attacker-controlled context, which creates opportunities to
   read the victim's data via [clever exploitation of side-channels][xsleaks].

[xsleaks]: https://github.com/xsleaks/xsleaks

Mitigations for these threats seem to break down into threeish categories: encrypted transport,
defenses against unintentional script execution ([CSP][], [Trusted Types][], etc.), and new
isolation primitives ([COOP][], [COEP][], [CORP][], etc). I'd suggest that we support selective
application of these diverse mitigations by adding arguments to the declaration, e.g. 
**`[SecureContext=(Transport,Isolation,Injection)]`**.

[CSP]: https://w3c.github.io/webappsec-csp/
[Trusted Types]: https://w3c.github.io/webappsec-trusted-types/dist/spec/
[COOP]: https://gist.github.com/annevk/6f2dd8c79c77123f39797f6bdac43f3e
[COEP]: https://mikewest.github.io/corpp/
[CORP]: https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header

## FAQ

### Parameterizing `[SecureContext]` is strange.

That's not a question.

### Fine. Parameterizing `[SecureContext]` is strange, _isn't it_?

Adding parameters to `[SecureContext]` is not my first choice. It would be ideal to simply upgrade
the restrictions we apply when `[SecureContext]` is present, and call it a day. Unfortunately, this
would break existing applications that rely upon APIs gated on that attribute, which is probably not
something we ought to do. I think we need something that will allow us to apply these new
restrictions incrementally.

An approach seems appealing is to rename the existing attribute to something like
`[SecureTransport]`. Running `sed -i '' -e 's/SecureContext/SecureTransport/g'` over all the
specifications would thereby make room for a redefinition of `[SecureContext]`, and we can decide
together which APIs require that higher standard, giving spec authors and developers a clear story
about the bar they need to meet.

Setting that bar, however, is a challenge, because I see several bars that might be relevant.

I expect us to be able to agree relatively easily on the set of APIs that require isolation defense,
as user agents are starting to align on a [post-Spectre threat model][post-spectre] and a set of
mitigations that address it. I'm hopeful that we'll be working towards defaulting the web experience
to requiring COOP/COEP/CORP assertions; attaching those restrictions to specific APIs as
stepping-stones along the way seems unobjectionable. Injection mitigation is unfortunately trickier.

[post-spectre]: https://chromium.googlesource.com/chromium/src/+/master/docs/security/side-channel-threat-model.md

I'm quite interested in requiring developers to do some work to defend themselves against injection
attacks, especially in the presence of APIs that grant access to things that are hard to reason
about in the web's general origin-based security model (here, I'm thinking of device-bound
capabilities, like WebUSB, clipboard, etc). This is a real line-drawing problem that I think we'll
need to work out together, but I expect that we'll collectively decide that this set of APIs is as
extensive as the set of APIs that should require isolation, which itself isn't as extensive as the
set of APIs that should require secure transport.

Given these distinctions, and given the apparent difficulty of deploying robust defenses against
injection attacks, I'm not sure it makes sense to have a single definition that we aspire to for
everything. Today, at least, more nuance seems valuable, and a distinction between injection and
isolation seems reasonable to encode into our understanding of secure context restrictions.

Assuming we agree that that's reasonable, I see two broad approaches to supporting that nuance:

1. Separating the mitigation categories into distinct attributes (e.g. `[X-Bikeshed-Transport]`,
   `[X-Bikeshed-Isolation]`, `[X-Bikeshed-Injection]`).

2. Binding the categories to a single attribute, as in `[SecureContext=(Transport,Isolation,Injection)]`.

The differences between these spellings seem largely aesthetic. I like that the latter binds all the
categories to the single `[SecureContext]` attribute, which makes it clear to me that they all are
taken into account when deciding whether their subject is exposed. I like that the former would make
it possible for us to change the spelling of the transport restriction to an opt-out rather than an
opt-in (e.g. we'd mark everything that currently lacks a `[SecureContext]` attribute with the
inverted `[UnsafelyAllowedViaNonsecureTransport]`), which could have some interesting impacts on
where we set the burden of proof in the conversation around API exposure.

Currently, I prefer the latter. I look forward to suggestions for alternatives, as I'm sure the
approaches I've outlined above are not exhaustive.

### What defenses would `[SecureContext=Isolation]` require?

Pages would need to assert [`Cross-Origin-Opener-Policy: same-origin`][COOP] and
[`Cross-Origin-Embedder-Policy: require-corp`][COEP]. This would have the effect of requiring their
dependencies to assert an appropriate [`Cross-Origin-Resource-Policy`][CORP].

### What APIs would require `[SecureContext=Isolation]`?

Certainly `SharedArrayBuffer` and `performance.{measureMemory(),now()}`. Probably future paint
timing APIs, and others we'll come up with over time. Ideally we'd make these the default behavior,
but we need some implementation experience before pushing for that seems reasonable.

In the short term, we could just call it a day by marking `window.performance` as
`[SecureContext=Transport,Isolation]` to avoid line-drawing arguments and appeals to the status quo,
but I suspect that will draw some pitchforks... so, let's decide how much we want to be yelled at,
shall we?

### What defenses would `[SecureContext=Injection]` require?

An excellent question! I think the requirements we'd start with would be along the lines of asserting
a `Content-Security-Policy` header (note: not via `<meta>`) that restricts `object-src`, `base-uri`,
and `script-src` in ways that more or less align with [StrictCSP][]. This would boil down to a policy
like that tracked by Chromium's [`kCSPWithReasonableRestrictions`][].

[StrictCSP]: https://csp.withgoogle.com/docs/strict-csp.html
[kCSPWithReasonableRestrictions]: https://chromium.googlesource.com/chromium/src/+/master/docs/security/web-mitigation-metrics.md

It would be nice to pull things like [Trusted Types][] in here as well. Let's see how that looks as we
agree upon the final details of an MVP, and get it out the door.

TODO(mkwst): Write down something about an opt-out along the lines of the proposals in
<https://github.com/mikewest/strict-csp-for-everyone>, and/or an alternative baseline of "You have
a CSP, and it has a `script-src`." (And note that I prefer the former, as the latter will break if
we ever want to raise the bar.)

### What APIs would require `[SecureContext=Injection]`?

Another excellent question! As noted above, I'm thinking about APIs that grant access to things that
are hard to reason about in the web's general origin-based security model. Device-bound capabilities
seem reasonable to consider, like WebUSB, clipboard, etc. Perhaps this could extend to "Anything
behind a user permission (e.g. geolocation, sensors, camera/microphone, etc)."

### What about `document.domain` and other web weirdnesses?

`document.domain` itself is neutered by `[SecureContext=Isolation]` via the same-origin restrictions
in the COOP/COEP mechanisms that enforce isolation more generally. This is instructive, as I'd like
to make sure that we're imposing requirements that tie back directly to the threat model discussed
above. There are a number of other things that I would love to deprecate, and this might be a
reasonable way of doing so, but it will be simpler to roll out if folks don't have to squint too
hard to understand why a given restriction is in place. `[SecureContext]` is something of a
sledgehammer, and it's not going to be appropriate for all deprecations (even ones that really annoy
me personally, like MIME sniffing!).
