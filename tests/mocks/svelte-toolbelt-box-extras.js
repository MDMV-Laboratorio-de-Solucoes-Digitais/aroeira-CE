// Plain JS mock for svelte-toolbelt box-extras.svelte.js
const isFunction = (v) => typeof v === "function";
const isObject = (v) => v !== null && typeof v === "object";

export const BoxSymbol = Symbol("box");
export const isWritableSymbol = Symbol("is-writable");

export function boxWith(getter, setter) {
  if (setter) {
    return {
      [BoxSymbol]: true,
      [isWritableSymbol]: true,
      get current() {
        return getter();
      },
      set current(v) {
        setter(v);
      },
    };
  }
  return {
    [BoxSymbol]: true,
    get current() {
      return getter();
    },
  };
}

export function isBox(value) {
  return isObject(value) && BoxSymbol in value;
}

export function isWritableBox(value) {
  return isBox(value) && isWritableSymbol in value;
}

export function simpleBox(initialValue) {
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

export function boxFrom(value) {
  if (isBox(value)) return value;
  if (isFunction(value)) return boxWith(value);
  return simpleBox(value);
}

export function boxFlatten(boxes) {
  return Object.entries(boxes).reduce((acc, [key, b]) => {
    if (!isBox(b)) {
      return Object.assign(acc, { [key]: b });
    }
    if (isWritableBox(b)) {
      Object.defineProperty(acc, key, {
        enumerable: true,
        configurable: true,
        get() {
          return b.current;
        },
        set(v) {
          b.current = v;
        },
      });
    } else {
      Object.defineProperty(acc, key, {
        enumerable: true,
        configurable: true,
        get() {
          return b.current;
        },
      });
    }
    return acc;
  }, {});
}

export function toReadonlyBox(b) {
  if (!isWritableBox(b)) return b;
  return {
    [BoxSymbol]: true,
    get current() {
      return b.current;
    },
  };
}
