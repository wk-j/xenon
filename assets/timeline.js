(function () {
  'use strict';

  var root = document.querySelector('[data-timeline]');
  if (!root) return;

  var search = document.querySelector('[data-timeline-search]');
  var topicLinks = Array.from(root.querySelectorAll('.timeline-topic-link'));
  var eventRows = Array.from(root.querySelectorAll('[data-event-row]'));
  var selectedEvent = eventRows.length ? 0 : -1;

  function isEditing(element) {
    if (!element) return false;
    return element.isContentEditable || /^(INPUT|SELECT|TEXTAREA|BUTTON|A)$/.test(element.tagName);
  }

  function navigate(url) {
    if (url) window.location.assign(url);
  }

  function selectEvent(index, focus) {
    if (!eventRows.length) return;
    if (selectedEvent >= 0) eventRows[selectedEvent].classList.remove('is-selected');
    selectedEvent = (index + eventRows.length) % eventRows.length;
    eventRows[selectedEvent].classList.add('is-selected');
    if (focus) {
      eventRows[selectedEvent].focus({ preventScroll: true });
      eventRows[selectedEvent].scrollIntoView({ block: 'nearest' });
    }
  }

  function clearSearch() {
    var url = new URL(window.location.href);
    if (!url.searchParams.has('q')) return false;
    url.searchParams.delete('q');
    navigate(url.pathname + url.search);
    return true;
  }

  if (selectedEvent >= 0) selectEvent(selectedEvent, false);

  document.addEventListener('keydown', function (event) {
    if (event.metaKey || event.ctrlKey || event.altKey) return;

    if (event.key === 'Escape') {
      if (clearSearch()) {
        event.preventDefault();
        return;
      }
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
      return;
    }

    if (isEditing(document.activeElement)) return;

    if (event.key === '/' && search) {
      event.preventDefault();
      search.focus();
      search.select();
      return;
    }

    if ((event.key === '[' || event.key === ']') && topicLinks.length) {
      event.preventDefault();
      var active = topicLinks.findIndex(function (link) {
        return link.getAttribute('aria-current') === 'page';
      });
      if (active < 0) active = 0;
      var delta = event.key === ']' ? 1 : -1;
      navigate(topicLinks[(active + delta + topicLinks.length) % topicLinks.length].href);
      return;
    }

    if (event.key === 'r') {
      event.preventDefault();
      navigate(root.getAttribute('data-reverse-url'));
      return;
    }

    if (event.key === 'j' || event.key === 'k') {
      event.preventDefault();
      selectEvent(selectedEvent + (event.key === 'j' ? 1 : -1), true);
      return;
    }

    if (event.key === 'Enter' && selectedEvent >= 0) {
      event.preventDefault();
      navigate(eventRows[selectedEvent].getAttribute('data-href'));
    }
  });
})();
