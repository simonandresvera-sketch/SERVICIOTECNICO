document.addEventListener("DOMContentLoaded", function () {
  // Control del navbar fijo / píldora flotante al hacer scroll
  const header = document.getElementById("site-header") || document.querySelector(".site-header");

  function updateNavbarOnScroll() {
    if (!header) return;
    if (window.scrollY > 25) {
      header.classList.add("scrolled");
    } else {
      header.classList.remove("scrolled");
    }
  }

  window.addEventListener("scroll", updateNavbarOnScroll, { passive: true });
  updateNavbarOnScroll();

  const revealElements = document.querySelectorAll(".scroll-reveal");

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      function (entries, obs) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            obs.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.12,
        rootMargin: "0px 0px -30px 0px",
      }
    );

    const delayClasses = ["delay-0", "delay-75", "delay-100", "delay-150", "delay-200", "delay-300"];

    revealElements.forEach(function (el, idx) {
      el.classList.add(delayClasses[idx % delayClasses.length]);
      observer.observe(el);
    });
  } else {
    revealElements.forEach(function (el) {
      el.classList.add("is-visible");
    });
  }
});
