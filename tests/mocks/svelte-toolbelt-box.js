// Mock for svelte-toolbelt box.svelte.js
import {
  boxFrom,
  boxWith,
  boxFlatten,
  toReadonlyBox,
  isBox,
  isWritableBox,
  BoxSymbol,
  isWritableSymbol,
} from "./svelte-toolbelt-box-extras.js";

export function box(initialValue) {
  let current = initialValue;
  return {
    [BoxSymbol]: true,
    [isWritableSymbol]: true,
    get current() {
      return current;
    },
    set current(v) {
      current = v;
    },
  };
}
box.from = boxFrom;
box.with = boxWith;
box.flatten = boxFlatten;
box.readonly = toReadonlyBox;
box.isBox = isBox;
box.isWritableBox = isWritableBox;
