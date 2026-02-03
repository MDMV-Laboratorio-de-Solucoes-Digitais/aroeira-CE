<script lang="ts" module>
  import { cn } from "$lib/utils.js";
  import { type VariantProps, tv } from "tailwind-variants";

  export const buttonVariants = tv({
    base: "focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive inline-flex shrink-0 items-center justify-center gap-2 rounded-md text-sm font-medium whitespace-nowrap transition-all outline-none focus-visible:ring-[3px] disabled:pointer-events-none disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground hover:bg-primary/90 shadow-xs",
        destructive:
          "bg-destructive hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60 text-white shadow-xs",
        outline:
          "bg-background hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 border shadow-xs",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 shadow-xs",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        sm: "h-8 gap-1.5 rounded-md px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-md px-6 has-[>svg]:px-4",
        icon: "size-9",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  });

  export type ButtonVariant = VariantProps<typeof buttonVariants>["variant"];
  export type ButtonSize = VariantProps<typeof buttonVariants>["size"];

  type BaseProps = {
    variant?: ButtonVariant;
    size?: ButtonSize;
    children?: import("svelte").Snippet;
  };

  export type ButtonProps = BaseProps &
    Record<string, unknown> & {
      class?: string;
      type?: "button" | "submit" | "reset";
      disabled?: boolean;
      href?: string;
      ref?: unknown;
      children?: import("svelte").Snippet;
      onclick?: (event: globalThis.MouseEvent) => void;
    };
</script>

<script lang="ts">
  import { base } from "$app/paths";
  import { isDangerousHref } from "$lib/utils/security";

  let {
    class: className,
    variant = "default",
    size = "default",
    ref = $bindable(),
    children,
    href,
    type = "button",
    disabled,
    ...restProps
  }: ButtonProps = $props();

  const withBase = (path: string) => (base ? `${base}${path}` : path);
</script>

{#if href}
  {@const { onclick, ...anchorProps } = restProps}
  {#if typeof href === "string" && href.startsWith("/") && !href.startsWith("//")}
    {@const internalHref = withBase(href)}
    {@const internalTarget = anchorProps.target as string | undefined}
    {@const internalProvidedRel = (anchorProps.rel as string | undefined) ?? ""}
    {@const internalSecurityRel =
      internalTarget === "_blank" ? "noopener noreferrer" : ""}
    {@const internalRel = [internalProvidedRel, internalSecurityRel]
      .filter(Boolean)
      .join(" ")}
    <a
      bind:this={ref}
      data-slot="button"
      {...anchorProps}
      rel={internalRel || undefined}
      target={internalTarget}
      class={cn(
        buttonVariants({ variant, size }),
        disabled ? "pointer-events-none" : "",
        className,
      )}
      href={internalHref}
      aria-disabled={disabled}
      tabindex={disabled ? -1 : undefined}
      onclick={(e: globalThis.MouseEvent) => {
        if (disabled) {
          e.preventDefault();
          e.stopPropagation();
          return;
        }
        onclick?.(e);
      }}
    >
      {@render children?.()}
    </a>
  {:else}
    {@const externalHref = href as string}
    <!-- Security: Validate URL schemes to prevent XSS (e.g. javascript:). -->
    <!-- Unsetting href for dangerous schemes while maintaining button rendering. -->
    {@const isDangerous = isDangerousHref(externalHref)}
    {@const anchorTarget = anchorProps.target as string | undefined}
    {@const providedRel = (anchorProps.rel as string | undefined) ?? ""}
    {@const securityRel =
      anchorTarget === "_blank" ? "noopener noreferrer" : ""}
    {@const externalRel = ["external", providedRel, securityRel]
      .filter(Boolean)
      .join(" ")}
    <a
      bind:this={ref}
      data-slot="button"
      {...anchorProps}
      class={cn(
        buttonVariants({ variant, size }),
        disabled || isDangerous ? "pointer-events-none" : "",
        className,
      )}
      href={isDangerous ? undefined : externalHref}
      rel={externalRel}
      target={anchorTarget}
      aria-disabled={disabled || isDangerous}
      tabindex={disabled || isDangerous ? -1 : undefined}
      onclick={(e: globalThis.MouseEvent) => {
        if (disabled || isDangerous) {
          e.preventDefault();
          e.stopPropagation();
          return;
        }
        onclick?.(e);
      }}
    >
      {@render children?.()}
    </a>
  {/if}
{:else}
  <button
    bind:this={ref}
    data-slot="button"
    {...restProps}
    class={cn(buttonVariants({ variant, size }), className)}
    {type}
    {disabled}
  >
    {@render children?.()}
  </button>
{/if}
