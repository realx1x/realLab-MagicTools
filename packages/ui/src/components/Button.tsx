import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

import { Tooltip } from './Tooltip';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'default' | 'compact' | 'icon';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  leadingIcon?: ReactNode;
  size?: ButtonSize;
  variant?: ButtonVariant;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    children,
    className = '',
    leadingIcon,
    size = 'default',
    type = 'button',
    variant = 'secondary',
    ...props
  },
  ref,
) {
  return (
    <button
      className={`ui-button ui-button--${variant} ui-button--${size} ${className}`.trim()}
      ref={ref}
      type={type}
      {...props}
    >
      {leadingIcon ? <span className="ui-button__icon">{leadingIcon}</span> : null}
      {children}
    </button>
  );
});

export interface IconButtonProps
  extends Omit<ButtonProps, 'aria-label' | 'children' | 'leadingIcon' | 'size'> {
  icon: ReactNode;
  label: string;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { icon, label, ...props },
  ref,
) {
  return (
    <Tooltip content={label}>
      <Button aria-label={label} ref={ref} size="icon" {...props}>
        {icon}
      </Button>
    </Tooltip>
  );
});
