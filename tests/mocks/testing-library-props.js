// Plain JS mock to bypass Svelte compiler
const createProps = (initialProps = {}) => {
  let currentProps = { ...(initialProps ?? {}) };

  const p = new Proxy(
    {},
    {
      get: (_, k) => currentProps[k],
      set: (_, k, v) => {
        currentProps[k] = v;
        return true;
      },
      ownKeys: () => Reflect.ownKeys(currentProps),
      getOwnPropertyDescriptor: (_, k) =>
        Object.getOwnPropertyDescriptor(currentProps, k),
    },
  );

  const update = (nextProps) => {
    currentProps = Object.assign({}, currentProps, nextProps);
  };

  return [p, update];
};
export { createProps };
