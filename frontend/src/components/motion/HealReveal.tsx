// Drop-in replacement for `SlideIn` in frontend/src/pages/Landing.tsx.
// Left/right "heal" reveal: the block is clipped shut from one side and the
// seam heals open when it scrolls into view. Alternate `dir` per section.
//
// Usage:  <HealReveal dir={-1}>…</HealReveal>   (dir 1 = opens from the left,
//         -1 = opens from the right, 0 = opens outward from the centre)

import { useEffect, useRef } from "react";
import { useReducedMotion } from "framer-motion";

type Dir = 1 | -1 | 0;

const closed = (d: Dir) =>
  d === -1 ? "inset(0 0 0 100%)" : d === 0 ? "inset(0 50% 0 50%)" : "inset(0 100% 0 0)";
const shift = (d: Dir) =>
  d === -1 ? "translate3d(-6%,0,0)" : d === 0 ? "none" : "translate3d(6%,0,0)";

export function HealReveal({
  children,
  dir = 1,
  duration = 1.05,
  className,
}: {
  children: React.ReactNode;
  dir?: Dir;
  duration?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    const el = ref.current;
    if (!el || reducedMotion) return;

    el.style.willChange = "clip-path, transform, opacity";
    el.style.clipPath = closed(dir);
    el.style.transform = shift(dir);
    el.style.opacity = "0.12";
    el.style.transition =
      `clip-path ${duration}s cubic-bezier(.16,1,.3,1),` +
      `transform ${duration}s cubic-bezier(.16,1,.3,1), opacity .75s ease`;

    let done = false;
    const open = () => {
      if (done) return;
      done = true;
      el.style.clipPath = "inset(0 0 0 0)";
      el.style.transform = "translate3d(0,0,0)";
      el.style.opacity = "1";
      // Drop the clip once the reveal finishes so nothing inside is cropped.
      window.setTimeout(() => {
        el.style.clipPath = "none";
        el.style.willChange = "auto";
      }, duration * 1000 + 350);
    };

    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && open()),
      { threshold: 0.06, rootMargin: "0px 0px -8% 0px" },
    );
    io.observe(el);

    // The landing page scrolls inside `.landing-scroll-container`, not the
    // document — keep a rect check as a safety net for that container.
    const scroller = el.closest(".landing-scroll-container") as HTMLElement | null;
    const check = () => {
      const vh = scroller ? scroller.clientHeight : window.innerHeight;
      if (el.getBoundingClientRect().top < vh * 0.92) open();
    };
    const target: HTMLElement | Window = scroller ?? window;
    target.addEventListener("scroll", check, { passive: true });
    window.addEventListener("resize", check);
    check();

    return () => {
      io.disconnect();
      target.removeEventListener("scroll", check);
      window.removeEventListener("resize", check);
    };
  }, [dir, duration, reducedMotion]);

  if (reducedMotion) return <div className={className}>{children}</div>;
  return (
    <div ref={ref} className={className}>
      {children}
    </div>
  );
}
