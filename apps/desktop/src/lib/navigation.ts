import { Home, Search, User, Settings } from "lucide-svelte";
import type { ComponentType } from "svelte";

export interface NavItem {
  href: string;
  label: string;
  icon: ComponentType;
}

export const navItems: NavItem[] = [
  { href: "/", label: "Home", icon: Home },
  { href: "/search", label: "Search", icon: Search },
  { href: "/profile", label: "Profile", icon: User },
  { href: "/settings", label: "Settings", icon: Settings },
];
