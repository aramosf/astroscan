import { Window } from 'happy-dom';

const window = new Window();
globalThis.HTMLElement = window.HTMLElement;
globalThis.customElements = window.customElements;

export default class MyElement extends HTMLElement {}

if (!customElements.get('my-element')) {
  customElements.define('my-element', MyElement);
}
