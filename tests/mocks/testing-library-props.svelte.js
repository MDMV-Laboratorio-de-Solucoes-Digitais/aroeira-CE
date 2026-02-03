// Patched version of @testing-library/svelte-core/src/props.svelte.js
// Removed JSDoc that causes Svelte 5 parsing errors in Vitest

const createProps = (initialProps = {}) => {
  let currentProps = { ...(initialProps ?? {}) };

  const props = new Proxy(
    {},
    {
      get(_, key) {
        return currentProps[key];
      },
      set(_, key, value) {
        currentProps[key] = value;
        return true;
      },
      has(_, key) {
        return Reflect.has(currentProps, key);
      },
      ownKeys() {
        return Reflect.ownKeys(currentProps);
      },
      getOwnPropertyDescriptor(_, key) {
        return Object.getOwnPropertyDescriptor(currentProps, key);
      },
    },
  );

  const update = (nextProps) => {
    currentProps = Object.assign({}, currentProps, nextProps);
  };

  return [props, update];
};

export { createProps };
