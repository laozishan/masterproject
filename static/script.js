const preloadedImages = new Set();

function findCardContainer(button) {
  const navigation = button ? button.closest(".card-navigation") : null;
  return navigation ? navigation.querySelector(".card-container") : null;
}

function scrollCards(container, distance) {
  if (!container) {
    return;
  }
  container.scrollBy({
    top: 0,
    left: distance,
    behavior: "smooth",
  });
  preloadNearbyImages(container);
}

function scrollToRight(container) {
  scrollCards(container || findCardContainer(window.event && window.event.currentTarget), 600);
}

function scrollToLeft(container) {
  scrollCards(container || findCardContainer(window.event && window.event.currentTarget), -600);
}

function preloadImage(src) {
  if (!src || preloadedImages.has(src)) {
    return;
  }
  preloadedImages.add(src);
  const image = new Image();
  image.decoding = "async";
  image.src = src;
}

function preloadNearbyImages(container) {
  const images = Array.from(container.querySelectorAll("img"));
  const leftEdge = container.scrollLeft;
  const rightEdge = leftEdge + container.clientWidth + 900;

  images.forEach((image) => {
    if (image.offsetLeft >= leftEdge && image.offsetLeft <= rightEdge) {
      preloadImage(image.currentSrc || image.src);
    }
  });
}

document.querySelectorAll(".prev-button").forEach((button) => {
  button.addEventListener("click", () => scrollCards(findCardContainer(button), -600));
});

document.querySelectorAll(".next-button").forEach((button) => {
  button.addEventListener("click", () => scrollCards(findCardContainer(button), 600));
});

document.querySelectorAll(".card-container").forEach((container) => {
  preloadNearbyImages(container);
  container.addEventListener("scroll", () => preloadNearbyImages(container), { passive: true });
});

const viewportPreloader = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        preloadImage(entry.target.currentSrc || entry.target.src);
        viewportPreloader.unobserve(entry.target);
      }
    });
  },
  { rootMargin: "600px" }
);

document.querySelectorAll("img[loading='lazy']").forEach((image) => {
  viewportPreloader.observe(image);
});
