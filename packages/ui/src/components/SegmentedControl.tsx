import { ToggleGroup as ToggleGroupPrimitive } from 'radix-ui';

export interface SegmentedControlItem {
  disabled?: boolean;
  label: string;
  value: string;
}

export interface SegmentedControlProps {
  ariaDescribedBy?: string | undefined;
  ariaLabel: string;
  items: readonly SegmentedControlItem[];
  onValueChange: (value: string) => void;
  value: string;
}

export function SegmentedControl({
  ariaDescribedBy,
  ariaLabel,
  items,
  onValueChange,
  value,
}: SegmentedControlProps) {
  return (
    <ToggleGroupPrimitive.Root
      aria-describedby={ariaDescribedBy}
      aria-label={ariaLabel}
      className="ui-segmented"
      onValueChange={(nextValue) => {
        if (nextValue) {
          onValueChange(nextValue);
        }
      }}
      type="single"
      value={value}
    >
      {items.map((item) => (
        <ToggleGroupPrimitive.Item
          className="ui-segmented__item"
          disabled={item.disabled ?? false}
          key={item.value}
          value={item.value}
        >
          {item.label}
        </ToggleGroupPrimitive.Item>
      ))}
    </ToggleGroupPrimitive.Root>
  );
}
