document.querySelectorAll('[id^=tab]').forEach(el => {
  el.addEventListener('keydown', e => {
    switch (e.key) {
      case 'Home': // go to first
        el.parentElement.firstElementChild.click();
        break;
      case 'End': // go to last
        el.parentElement.lastElementChild.click();
        break;
      case 'ArrowUp':
      case 'ArrowLeft': // go to previous if possible
        if (el.previousElementSibling) el.previousElementSibling.click();
        break;
      case 'ArrowDown':
      case 'ArrowRight': // go to next if possible
        if (el.nextElementSibling) el.nextElementSibling.click();
        break;
      case 'Enter':
        el.click();
        break;
    }
  });
});
