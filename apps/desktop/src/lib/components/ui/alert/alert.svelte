<script lang="ts">
  import { cn } from "$lib/utils";
  import { tv, type VariantProps } from "tailwind-variants";

  const alertVariants = tv({
    base: "relative w-full rounded-lg border p-4 [&>svg~*]:pl-7 [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-foreground",
    variants: {
      variant: {
        default: "bg-background text-foreground",
        destructive:
          "border-destructive/50 text-destructive dark:border-destructive [&>svg]:text-destructive bg-destructive/10",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  });

  type Props = {
    class?: string;
    variant?: VariantProps<typeof alertVariants>["variant"];
    children?: import("svelte").Snippet;
  } & Record<string, unknown>;

  let { class: className, variant, children, ...restProps }: Props = $props();
</script>

<div
  role="alert"
  class={cn(alertVariants({ variant }), className)}
  {...restProps}
>
  {@render children?.()}
</div>
