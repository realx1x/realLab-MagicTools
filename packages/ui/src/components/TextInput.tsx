import { forwardRef, type InputHTMLAttributes } from 'react';

export interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean;
}

export const TextInput = forwardRef<HTMLInputElement, TextInputProps>(function TextInput(
  { className = '', invalid = false, ...props },
  ref,
) {
  return (
    <input
      aria-invalid={invalid || undefined}
      className={`ui-input ${className}`.trim()}
      ref={ref}
      {...props}
    />
  );
});
