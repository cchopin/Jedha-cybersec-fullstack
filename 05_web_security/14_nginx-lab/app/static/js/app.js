document.addEventListener("DOMContentLoaded", function () {
  const flashes = document.querySelectorAll(".flash");

  flashes.forEach((flash) => {
    setTimeout(() => {
      flash.style.opacity = "0";
      setTimeout(() => {
        flash.style.display = "none";
      }, 300);
    }, 3000);
  });

  const deleteLinks = document.querySelectorAll(".delete");

  deleteLinks.forEach((link) => {
    link.addEventListener("click", function (e) {
      if (!confirm("Êtes-vous sûr de vouloir supprimer cette tâche?")) {
        e.preventDefault();
      }
    });
  });
});
