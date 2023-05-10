// page scroller

const prevButtons = document.querySelectorAll(".prev-button");
const nextButtons = document.querySelectorAll(".next-button");
const cardContainers = document.querySelectorAll(".card-container");

function scrollToRight(container) {
  container.scrollBy({
    top: 0,
    left: 600, // Adjust the scroll amount based on card width
    behavior: "smooth",
  });
}

function scrollToLeft(container) {
  container.scrollBy({
    top: 0,
    left: -600, // Adjust the scroll amount based on  card width
    behavior: "smooth",
  });
}

// Bind the events to the buttons
for (let i = 0; i < prevButtons.length; i++) {
  prevButtons[i].addEventListener("click", () => {
    scrollToLeft(cardContainers[i]);
  });
}

for (let i = 0; i < nextButtons.length; i++) {
  nextButtons[i].addEventListener("click", () => {
    scrollToRight(cardContainers[i]);
  });
}
