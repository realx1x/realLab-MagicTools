import type { ReactNode } from 'react';
import { DropdownMenu as DropdownMenuPrimitive } from 'radix-ui';

export interface MenuItem {
  danger?: boolean;
  disabled?: boolean;
  icon?: ReactNode;
  id: string;
  label: string;
  onSelect: () => void;
}

export interface MenuProps {
  align?: 'start' | 'center' | 'end';
  items: readonly MenuItem[];
  label: string;
  trigger: ReactNode;
}

export function Menu({ align = 'end', items, label, trigger }: MenuProps) {
  return (
    <DropdownMenuPrimitive.Root>
      <DropdownMenuPrimitive.Trigger aria-label={label} asChild>
        {trigger}
      </DropdownMenuPrimitive.Trigger>
      <DropdownMenuPrimitive.Portal>
        <DropdownMenuPrimitive.Content align={align} className="ui-menu" sideOffset={6}>
          {items.map((item) => (
            <DropdownMenuPrimitive.Item
              className={item.danger ? 'ui-menu__item ui-menu__item--danger' : 'ui-menu__item'}
              disabled={item.disabled ?? false}
              key={item.id}
              onSelect={() => item.onSelect()}
            >
              {item.icon ? <span className="ui-menu__icon">{item.icon}</span> : null}
              <span>{item.label}</span>
            </DropdownMenuPrimitive.Item>
          ))}
        </DropdownMenuPrimitive.Content>
      </DropdownMenuPrimitive.Portal>
    </DropdownMenuPrimitive.Root>
  );
}
