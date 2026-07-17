import {
  forwardRef,
  useDeferredValue,
  useEffect,
  useId,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import {
  defaultRangeExtractor,
  useVirtualizer,
  type Range,
  type Virtualizer,
} from '@tanstack/react-virtual';
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  CircleCheck,
  CircleHelp,
  CirclePause,
  CircleStop,
  Moon,
  Search,
  ShieldAlert,
  TriangleAlert,
  X,
  type LucideIcon,
} from 'lucide-react';

import type {
  FieldValue,
  PortBinding,
  ProcessInstanceKey,
  ProcessRecord,
  ProcessStatus,
  ProjectAssociationEvidence,
  ProjectEvidence,
} from '@dpm/generated-types';
import { IconButton, SegmentedControl, TextInput, Tooltip } from '@dpm/ui';

import {
  buildProcessTableRows,
  processFilterItems,
  type FieldPresentation as ModelFieldPresentation,
  type ProcessFilter,
  type ProcessSortKey,
  type ProcessTableRow,
  type SortDirection,
} from './processTableModel';

const PROCESS_ROW_HEIGHT = 44;
const PROCESS_TABLE_HEADER_HEIGHT = 36;
const PROCESS_COLUMN_COUNT = 8;
const PROCESS_PAGE_SIZE = 25;
const MAX_VISIBLE_PROCESS_KEYS = 64;
const processTableModeItems = [
  { label: 'Virtual', value: 'virtual' },
  { label: 'Paged', value: 'paged' },
] as const;

type ProcessTableMode = (typeof processTableModeItems)[number]['value'];

interface ProcessTableProps {
  onSelectionChange: (key: string) => void;
  onVisibleProcessKeysChange: (keys: ReadonlyArray<ProcessInstanceKey>) => void;
  processes: ReadonlyArray<ProcessRecord>;
  selectedKey: string | null;
}

export interface ProcessTableHandle {
  focusProcess(key: string): void;
}

interface ProcessSort {
  direction: SortDirection;
  key: ProcessSortKey;
}

interface FieldPresentation {
  kind: 'accessLimited' | 'known' | 'missing' | 'notSupported' | 'unknown';
  text: string;
  title?: string;
}

interface StatusPresentation extends FieldPresentation {
  Icon: LucideIcon;
  tone: 'muted' | 'neutral' | 'running' | 'warning';
}

interface SortableHeaderProps {
  className: string;
  colIndex: number;
  label: string;
  onSort: (key: ProcessSortKey) => void;
  sort: ProcessSort;
  sortKey: ProcessSortKey;
}

export const ProcessTable = forwardRef<ProcessTableHandle, ProcessTableProps>(function ProcessTable(
  { onSelectionChange, onVisibleProcessKeysChange, processes, selectedKey },
  ref,
) {
  const [filter, setFilter] = useState<ProcessFilter>('all');
  const [focusedKey, setFocusedKey] = useState<string | null>(null);
  const [pageIndex, setPageIndex] = useState(0);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<ProcessSort>({ direction: 'asc', key: 'name' });
  const [tableMode, setTableMode] = useState<ProcessTableMode>('virtual');
  const deferredSearch = useDeferredValue(search);
  const countId = useId();
  const tableId = useId();
  const scrollElement = useRef<HTMLDivElement>(null);
  const rowElements = useRef(new Map<string, HTMLDivElement>());
  const visibleProcessKeysSignature = useRef<string | null>(null);
  const rows = useMemo(
    () =>
      buildProcessTableRows(processes, {
        filter,
        search: deferredSearch,
        sort,
      }),
    [deferredSearch, filter, processes, sort],
  );
  const selectedIndex =
    selectedKey === null ? -1 : rows.findIndex((row) => row.key === selectedKey);
  const focusedIndex = focusedKey === null ? -1 : rows.findIndex((row) => row.key === focusedKey);
  const activeIndex =
    focusedIndex >= 0
      ? focusedIndex
      : selectedIndex >= 0
        ? selectedIndex
        : rows.length > 0
          ? 0
          : -1;
  const activeKey = activeIndex >= 0 ? (rows[activeIndex]?.key ?? null) : null;
  const pageCount = Math.max(1, Math.ceil(rows.length / PROCESS_PAGE_SIZE));
  const currentPageIndex = Math.min(pageIndex, pageCount - 1);
  const pageStartIndex = currentPageIndex * PROCESS_PAGE_SIZE;
  const pageEndIndex = Math.min(pageStartIndex + PROCESS_PAGE_SIZE, rows.length);
  const pagedRows = rows.slice(pageStartIndex, pageEndIndex);
  const pagedActiveIndex =
    focusedIndex >= pageStartIndex && focusedIndex < pageEndIndex
      ? focusedIndex
      : selectedIndex >= pageStartIndex && selectedIndex < pageEndIndex
        ? selectedIndex
        : pageStartIndex < pageEndIndex
          ? pageStartIndex
          : -1;
  const pagedActiveKey = pagedActiveIndex >= 0 ? (rows[pagedActiveIndex]?.key ?? null) : null;
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    estimateSize: () => PROCESS_ROW_HEIGHT,
    getItemKey: (index) => rows[index]?.key ?? index,
    getScrollElement: () => scrollElement.current,
    overscan: 10,
    rangeExtractor: (range) => retainActiveIndex(range, activeIndex),
    scrollMargin: PROCESS_TABLE_HEADER_HEIGHT,
    scrollPaddingStart: PROCESS_TABLE_HEADER_HEIGHT,
  });
  const virtualRangeStart = rowVirtualizer.range?.startIndex ?? -1;
  const virtualRangeEnd = rowVirtualizer.range?.endIndex ?? -1;
  const visibleProcessKeys = useMemo(
    () =>
      tableMode === 'paged'
        ? collectVisibleProcessKeys(rows, pageStartIndex, pageEndIndex - 1)
        : collectVisibleProcessKeys(rows, virtualRangeStart, virtualRangeEnd),
    [pageEndIndex, pageStartIndex, rows, tableMode, virtualRangeEnd, virtualRangeStart],
  );
  const currentVisibleProcessKeysSignature = processKeysSignature(visibleProcessKeys);
  useEffect(() => {
    setPageIndex((current) => Math.min(current, pageCount - 1));
  }, [pageCount]);
  useEffect(() => {
    if (visibleProcessKeysSignature.current === currentVisibleProcessKeysSignature) {
      return;
    }
    visibleProcessKeysSignature.current = currentVisibleProcessKeysSignature;
    onVisibleProcessKeysChange(visibleProcessKeys);
  }, [currentVisibleProcessKeysSignature, onVisibleProcessKeysChange, visibleProcessKeys]);
  useImperativeHandle(
    ref,
    () => ({
      focusProcess(key) {
        const index = rows.findIndex((row) => row.key === key);
        if (index >= 0) {
          setFocusedKey(key);
          if (tableMode === 'paged') {
            setPageIndex(Math.floor(index / PROCESS_PAGE_SIZE));
            focusPagedRow(key, rowElements);
          } else {
            focusVirtualRow(index, rows, rowVirtualizer, rowElements);
          }
        } else {
          scrollElement.current?.focus({ preventScroll: true });
        }
      },
    }),
    [rowVirtualizer, rows, tableMode],
  );

  const updateSort = (key: ProcessSortKey) => {
    setSort((current) => ({
      direction:
        current.key === key
          ? current.direction === 'asc'
            ? 'desc'
            : 'asc'
          : key === 'name' || key === 'project' || key === 'status'
            ? 'asc'
            : 'desc',
      key,
    }));
  };

  return (
    <section aria-label="Process table" className="process-table-region">
      <div className="process-toolbar">
        <SegmentedControl
          ariaLabel="Filter processes"
          items={processFilterItems}
          onValueChange={(value) => {
            if (processFilterItems.some((item) => item.value === value)) {
              setFilter(value as ProcessFilter);
            }
          }}
          value={filter}
        />
        <div className="process-table-mode">
          <SegmentedControl
            ariaLabel="Process table display mode"
            items={processTableModeItems}
            onValueChange={(value) => {
              if (value === 'virtual' || value === 'paged') {
                if (value === 'paged' && activeIndex >= 0) {
                  setPageIndex(Math.floor(activeIndex / PROCESS_PAGE_SIZE));
                }
                setTableMode(value);
              }
            }}
            value={tableMode}
          />
        </div>
        <div className="process-search">
          <Search aria-hidden="true" className="process-search-icon" size={15} strokeWidth={1.8} />
          <TextInput
            aria-label="Search processes"
            className="process-search-input"
            onChange={(event) => setSearch(event.currentTarget.value)}
            placeholder="Search name, project, PID, or port"
            spellCheck={false}
            type="search"
            value={search}
          />
          {search ? (
            <IconButton
              className="process-search-clear"
              icon={<X aria-hidden="true" size={15} strokeWidth={1.8} />}
              label="Clear process search"
              onClick={() => setSearch('')}
              variant="ghost"
            />
          ) : null}
        </div>
        <span aria-live="polite" className="process-result-count" id={countId} role="status">
          {formatResultCount(rows.length, processes.length)}
        </span>
      </div>
      <div
        aria-colcount={PROCESS_COLUMN_COUNT}
        aria-describedby={countId}
        aria-rowcount={rows.length + 1}
        className="process-table-viewport"
        id={tableId}
        ref={scrollElement}
        role="table"
        tabIndex={-1}
      >
        <div className="process-table-grid process-table-header" role="row">
          <SortableHeader
            className="process-column--status"
            colIndex={1}
            label="Status"
            onSort={updateSort}
            sort={sort}
            sortKey="status"
          />
          <SortableHeader
            className="process-column--name"
            colIndex={2}
            label="Name"
            onSort={updateSort}
            sort={sort}
            sortKey="name"
          />
          <SortableHeader
            className="process-column--project"
            colIndex={3}
            label="Project"
            onSort={updateSort}
            sort={sort}
            sortKey="project"
          />
          <SortableHeader
            className="process-column--ports"
            colIndex={4}
            label="Ports"
            onSort={updateSort}
            sort={sort}
            sortKey="ports"
          />
          <SortableHeader
            className="process-column--cpu process-column--numeric"
            colIndex={5}
            label="CPU"
            onSort={updateSort}
            sort={sort}
            sortKey="cpu"
          />
          <SortableHeader
            className="process-column--memory process-column--numeric"
            colIndex={6}
            label="Memory"
            onSort={updateSort}
            sort={sort}
            sortKey="memory"
          />
          <SortableHeader
            className="process-column--uptime process-column--numeric"
            colIndex={7}
            label="Uptime"
            onSort={updateSort}
            sort={sort}
            sortKey="uptime"
          />
          <SortableHeader
            className="process-column--pid process-column--numeric"
            colIndex={8}
            label="PID"
            onSort={updateSort}
            sort={sort}
            sortKey="pid"
          />
        </div>
        {rows.length === 0 ? (
          <div className="process-table-empty" role="rowgroup">
            <div role="row">
              <div aria-colspan={PROCESS_COLUMN_COUNT} role="cell">
                <strong>
                  {processes.length === 0 ? 'No processes found' : 'No matching processes'}
                </strong>
                <span>
                  {processes.length === 0
                    ? 'The synchronized process snapshot is empty.'
                    : 'Adjust the active filter or search.'}
                </span>
              </div>
            </div>
          </div>
        ) : (
          <div
            className={`process-table-body process-table-body--${tableMode}`}
            role="rowgroup"
            style={
              tableMode === 'virtual' ? { height: `${rowVirtualizer.getTotalSize()}px` } : undefined
            }
          >
            {tableMode === 'virtual'
              ? rowVirtualizer.getVirtualItems().map((virtualRow) => {
                  const row = rows[virtualRow.index];
                  if (!row) {
                    return null;
                  }
                  return (
                    <ProcessRow
                      activeKey={activeKey}
                      key={row.key}
                      layout="virtual"
                      onMoveFocus={(index) =>
                        moveVirtualRowFocus(index, rows, rowVirtualizer, rowElements, setFocusedKey)
                      }
                      onSelect={(key) => {
                        setFocusedKey(key);
                        onSelectionChange(key);
                      }}
                      row={row}
                      rowElements={rowElements}
                      rowIndex={virtualRow.index}
                      selected={selectedKey === row.key}
                      virtualStart={virtualRow.start}
                    />
                  );
                })
              : pagedRows.map((row, indexOnPage) => {
                  const rowIndex = pageStartIndex + indexOnPage;
                  return (
                    <ProcessRow
                      activeKey={pagedActiveKey}
                      key={row.key}
                      layout="paged"
                      onMoveFocus={(index) =>
                        movePagedRowFocus(index, rows, rowElements, setFocusedKey, setPageIndex)
                      }
                      onSelect={(key) => {
                        setFocusedKey(key);
                        onSelectionChange(key);
                      }}
                      row={row}
                      rowElements={rowElements}
                      rowIndex={rowIndex}
                      selected={selectedKey === row.key}
                    />
                  );
                })}
          </div>
        )}
      </div>
      {tableMode === 'paged' ? (
        <nav aria-label="Process table pages" className="process-pagination">
          <IconButton
            aria-controls={tableId}
            className="process-pagination-button"
            disabled={currentPageIndex === 0}
            icon={<ChevronLeft aria-hidden="true" size={16} strokeWidth={1.8} />}
            label="Previous page"
            onClick={() => setPageIndex(Math.max(0, currentPageIndex - 1))}
            variant="ghost"
          />
          <span aria-live="polite" className="process-pagination-status">
            Page {currentPageIndex + 1} of {pageCount}
          </span>
          <IconButton
            aria-controls={tableId}
            className="process-pagination-button"
            disabled={currentPageIndex >= pageCount - 1}
            icon={<ChevronRight aria-hidden="true" size={16} strokeWidth={1.8} />}
            label="Next page"
            onClick={() => setPageIndex(Math.min(pageCount - 1, currentPageIndex + 1))}
            variant="ghost"
          />
          <span className="process-pagination-total">{formatPageResultCount(rows.length)}</span>
        </nav>
      ) : null}
    </section>
  );
});

function retainActiveIndex(range: Range, activeIndex: number) {
  const indexes = defaultRangeExtractor(range);
  if (activeIndex < 0 || indexes.includes(activeIndex)) {
    return indexes;
  }
  return [...indexes, activeIndex].sort((left, right) => left - right);
}

function collectVisibleProcessKeys(
  rows: ReadonlyArray<ProcessTableRow>,
  rawStartIndex: number,
  rawEndIndex: number,
): ProcessInstanceKey[] {
  const startIndex = Math.max(0, rawStartIndex);
  const endIndex = Math.min(rawEndIndex, rows.length - 1);
  if (rawStartIndex < 0 || endIndex < startIndex) {
    return [];
  }

  const keys: ProcessInstanceKey[] = [];
  const seen = new Set<string>();
  for (
    let index = startIndex;
    index <= endIndex && keys.length < MAX_VISIBLE_PROCESS_KEYS;
    index += 1
  ) {
    const instanceKey = rows[index]?.process.instanceKey;
    if (!instanceKey) {
      continue;
    }
    const signature = processKeySignature(instanceKey);
    if (seen.has(signature)) {
      continue;
    }
    seen.add(signature);
    keys.push(copyProcessInstanceKey(instanceKey));
  }
  return keys;
}

function processKeysSignature(keys: ReadonlyArray<ProcessInstanceKey>): string {
  return JSON.stringify(keys.map(processKeyTuple));
}

function processKeySignature(key: ProcessInstanceKey): string {
  return JSON.stringify(processKeyTuple(key));
}

function processKeyTuple(key: ProcessInstanceKey): [string, number, string] {
  return [key.bootId, key.pid, key.nativeStartTime];
}

function copyProcessInstanceKey(key: ProcessInstanceKey): ProcessInstanceKey {
  return {
    bootId: key.bootId,
    nativeStartTime: key.nativeStartTime,
    pid: key.pid,
  };
}

function SortableHeader({
  className,
  colIndex,
  label,
  onSort,
  sort,
  sortKey,
}: SortableHeaderProps) {
  const active = sort.key === sortKey;
  const SortIcon = !active ? ChevronsUpDown : sort.direction === 'asc' ? ArrowUp : ArrowDown;
  return (
    <div
      aria-colindex={colIndex}
      aria-sort={active ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={`process-table-cell process-table-heading ${className}`}
      role="columnheader"
    >
      <button onClick={() => onSort(sortKey)} type="button">
        <span>{label}</span>
        <SortIcon aria-hidden="true" size={13} strokeWidth={1.8} />
      </button>
    </div>
  );
}

interface ProcessRowProps {
  activeKey: string | null;
  layout: ProcessTableMode;
  onMoveFocus: (index: number) => void;
  onSelect: (key: string) => void;
  row: ProcessTableRow;
  rowElements: React.MutableRefObject<Map<string, HTMLDivElement>>;
  rowIndex: number;
  selected: boolean;
  virtualStart?: number;
}

function ProcessRow({
  activeKey,
  layout,
  onMoveFocus,
  onSelect,
  row,
  rowElements,
  rowIndex,
  selected,
  virtualStart,
}: ProcessRowProps) {
  const status = presentStatus(row.process.status);
  const name = presentModeledField(row.name, (value) => value.trim() || 'Unnamed');
  const project = presentProject(row.process.projectAssociation, row.project);
  const ports = presentPorts(row.process.portBindings, row.ports);
  const cpu = presentField(row.process.cpuPercent, formatCpu);
  const memory = presentField(row.process.memoryBytes, formatBytes);
  const uptime = presentField(row.process.startedAt, formatUptime);
  const StatusIcon = status.Icon;

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    let nextIndex: number | null = null;
    if (event.key === 'ArrowDown') {
      nextIndex = Math.min(rowIndex + 1, Number.MAX_SAFE_INTEGER);
    } else if (event.key === 'ArrowUp') {
      nextIndex = Math.max(rowIndex - 1, 0);
    } else if (event.key === 'Home') {
      nextIndex = 0;
    } else if (event.key === 'End') {
      nextIndex = Number.MAX_SAFE_INTEGER;
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onSelect(row.key);
    }
    if (nextIndex !== null) {
      event.preventDefault();
      onMoveFocus(nextIndex);
    }
  };

  return (
    <div
      aria-rowindex={rowIndex + 2}
      aria-selected={selected}
      className={`process-table-grid process-table-row process-table-row--${layout}`}
      data-selected={selected || undefined}
      onClick={(event) => {
        event.currentTarget.focus({ preventScroll: true });
        onSelect(row.key);
      }}
      onKeyDown={handleKeyDown}
      ref={(element) => {
        if (element) {
          rowElements.current.set(row.key, element);
        } else {
          rowElements.current.delete(row.key);
        }
      }}
      role="row"
      style={
        layout === 'virtual'
          ? {
              transform: `translateY(${(virtualStart ?? 0) - PROCESS_TABLE_HEADER_HEIGHT}px)`,
            }
          : { position: 'relative', transform: 'none' }
      }
      tabIndex={activeKey === row.key ? 0 : -1}
    >
      <div
        aria-colindex={1}
        className="process-table-cell process-column--status"
        data-field-kind={status.kind}
        data-tone={status.tone}
        role="cell"
        title={status.title ?? status.text}
      >
        <StatusIcon aria-hidden="true" size={14} strokeWidth={1.8} />
        <span>{status.text}</span>
      </div>
      <div
        aria-colindex={2}
        className="process-table-cell process-column--name"
        data-field-kind={name.kind}
        role="cell"
        title={name.title ?? name.text}
      >
        <span className="process-access-slot">
          {row.process.accessLevel === 'full' ? null : (
            <Tooltip
              content={row.process.accessLevel === 'denied' ? 'Access denied' : 'Access limited'}
            >
              <ShieldAlert aria-label="Process access limited" size={14} strokeWidth={1.8} />
            </Tooltip>
          )}
        </span>
        <span className="process-cell-text">{name.text}</span>
      </div>
      <div
        aria-colindex={3}
        className="process-table-cell process-column--project"
        data-field-kind={project.kind}
        role="cell"
        title={project.title ?? project.text}
      >
        <span className="process-cell-text">{project.text}</span>
      </div>
      <div
        aria-colindex={4}
        className="process-table-cell process-column--ports process-mono"
        data-field-kind={ports.kind}
        role="cell"
        title={ports.title ?? ports.text}
      >
        <span className="process-cell-text">{ports.text}</span>
      </div>
      <div
        aria-colindex={5}
        className="process-table-cell process-column--cpu process-column--numeric process-mono"
        data-field-kind={cpu.kind}
        role="cell"
        title={cpu.title ?? cpu.text}
      >
        {cpu.text}
      </div>
      <div
        aria-colindex={6}
        className="process-table-cell process-column--memory process-column--numeric process-mono"
        data-field-kind={memory.kind}
        role="cell"
        title={memory.title ?? memory.text}
      >
        {memory.text}
      </div>
      <div
        aria-colindex={7}
        className="process-table-cell process-column--uptime process-column--numeric process-mono"
        data-field-kind={uptime.kind}
        role="cell"
        title={uptime.title ?? uptime.text}
      >
        {uptime.text}
      </div>
      <div
        aria-colindex={8}
        className="process-table-cell process-column--pid process-column--numeric process-mono"
        role="cell"
      >
        {row.pid.toLocaleString()}
      </div>
    </div>
  );
}

function moveVirtualRowFocus(
  requestedIndex: number,
  rows: ReadonlyArray<ProcessTableRow>,
  virtualizer: Virtualizer<HTMLDivElement, Element>,
  rowElements: React.MutableRefObject<Map<string, HTMLDivElement>>,
  setFocusedKey: (key: string) => void,
) {
  const index = Math.max(0, Math.min(requestedIndex, rows.length - 1));
  const row = rows[index];
  if (!row) {
    return;
  }
  setFocusedKey(row.key);
  focusVirtualRow(index, rows, virtualizer, rowElements);
}

function movePagedRowFocus(
  requestedIndex: number,
  rows: ReadonlyArray<ProcessTableRow>,
  rowElements: React.MutableRefObject<Map<string, HTMLDivElement>>,
  setFocusedKey: (key: string) => void,
  setPageIndex: (index: number) => void,
) {
  const index = Math.max(0, Math.min(requestedIndex, rows.length - 1));
  const row = rows[index];
  if (!row) {
    return;
  }
  setFocusedKey(row.key);
  setPageIndex(Math.floor(index / PROCESS_PAGE_SIZE));
  focusPagedRow(row.key, rowElements);
}

function focusVirtualRow(
  index: number,
  rows: ReadonlyArray<ProcessTableRow>,
  virtualizer: Virtualizer<HTMLDivElement, Element>,
  rowElements: React.MutableRefObject<Map<string, HTMLDivElement>>,
) {
  const row = rows[index];
  if (!row) {
    return;
  }
  virtualizer.scrollToIndex(index, { align: 'auto' });
  requestAnimationFrame(() => {
    requestAnimationFrame(() => rowElements.current.get(row.key)?.focus({ preventScroll: true }));
  });
}

function focusPagedRow(
  key: string,
  rowElements: React.MutableRefObject<Map<string, HTMLDivElement>>,
) {
  requestAnimationFrame(() => {
    requestAnimationFrame(() => rowElements.current.get(key)?.focus({ preventScroll: true }));
  });
}

function presentStatus(value: FieldValue<ProcessStatus>): StatusPresentation {
  if (typeof value === 'object' && 'known' in value) {
    switch (value.known) {
      case 'running':
        return { Icon: CircleCheck, kind: 'known', text: 'Running', tone: 'running' };
      case 'sleeping':
        return { Icon: Moon, kind: 'known', text: 'Sleeping', tone: 'neutral' };
      case 'stopped':
        return { Icon: CirclePause, kind: 'known', text: 'Stopped', tone: 'warning' };
      case 'zombie':
        return { Icon: TriangleAlert, kind: 'known', text: 'Zombie', tone: 'warning' };
      case 'exited':
        return { Icon: CircleStop, kind: 'known', text: 'Exited', tone: 'muted' };
      case 'unknown':
        return { Icon: CircleHelp, kind: 'unknown', text: 'Unknown', tone: 'muted' };
    }
  }
  const field = presentField<ProcessStatus>(value, (status) => status);
  return {
    ...field,
    Icon: field.kind === 'accessLimited' ? ShieldAlert : CircleHelp,
    tone: field.kind === 'accessLimited' ? 'warning' : 'muted',
  };
}

function presentField<T>(value: FieldValue<T>, format: (known: T) => string): FieldPresentation {
  if (typeof value === 'object') {
    if ('known' in value) {
      return { kind: 'known', text: format(value.known) };
    }
    return {
      kind: 'accessLimited',
      text: 'Restricted',
      title: value.accessLimited.reason ?? 'Access to this field is limited.',
    };
  }
  if (value === 'notSupported') {
    return { kind: 'notSupported', text: 'Not supported' };
  }
  return { kind: 'unknown', text: 'Unknown' };
}

function presentModeledField<T>(
  value: ModelFieldPresentation<T>,
  formatKnown: (known: T, text: string) => string,
  missingText = 'None',
): FieldPresentation {
  if (value.kind === 'known' && value.value !== null) {
    return { kind: 'known', text: formatKnown(value.value, value.text) };
  }
  switch (value.kind) {
    case 'accessLimited':
      return {
        kind: 'accessLimited',
        text: 'Restricted',
        title: value.reason ?? 'Access to this field is limited.',
      };
    case 'missing':
      return { kind: 'missing', text: missingText };
    case 'notSupported':
      return { kind: 'notSupported', text: 'Not supported' };
    case 'known':
    case 'unknown':
      return { kind: 'unknown', text: 'Unknown' };
  }
}

function presentProject(
  value: ProjectEvidence<ProjectAssociationEvidence>,
  modeled: ModelFieldPresentation<string>,
): FieldPresentation {
  const presentation = presentModeledField(modeled, (projectId) => projectId, 'No project');
  if (presentation.kind === 'known' && typeof value === 'object' && 'known' in value) {
    return {
      ...presentation,
      title: `${value.known.projectId} - ${value.known.registeredRoot}`,
    };
  }
  return presentation;
}

function presentPorts(
  value: FieldValue<Array<PortBinding>>,
  modeled: ModelFieldPresentation<readonly PortBinding[]>,
): FieldPresentation {
  const presentation = presentModeledField(modeled, (bindings, text) =>
    bindings.length === 0 ? 'None' : text.replaceAll(' · ', ', '),
  );
  if (
    presentation.kind !== 'known' ||
    typeof value !== 'object' ||
    !('known' in value) ||
    value.known.length === 0
  ) {
    return presentation;
  }
  const title = [...value.known]
    .sort((left, right) => left.localPort - right.localPort)
    .map(
      (binding) => `${binding.protocol.toUpperCase()} ${binding.localAddress}:${binding.localPort}`,
    )
    .join('\n');
  return { ...presentation, title };
}

function formatCpu(value: number) {
  return Number.isFinite(value) ? `${Math.max(0, value).toFixed(value < 10 ? 1 : 0)}%` : 'Unknown';
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return 'Unknown';
  }
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 || value >= 10 ? 0 : 1)} ${units[unit]}`;
}

function formatUptime(startedAt: string) {
  const startedAtMs = Date.parse(startedAt);
  if (!Number.isFinite(startedAtMs)) {
    return 'Unknown';
  }
  const elapsedMinutes = Math.max(0, Math.floor((Date.now() - startedAtMs) / 60_000));
  if (elapsedMinutes < 1) {
    return '<1m';
  }
  if (elapsedMinutes < 60) {
    return `${elapsedMinutes}m`;
  }
  const elapsedHours = Math.floor(elapsedMinutes / 60);
  if (elapsedHours < 24) {
    return `${elapsedHours}h ${elapsedMinutes % 60}m`;
  }
  return `${Math.floor(elapsedHours / 24)}d ${elapsedHours % 24}h`;
}

function formatResultCount(filtered: number, total: number) {
  const visible = filtered.toLocaleString();
  const available = total.toLocaleString();
  return filtered === total ? `${available} total` : `${visible} of ${available}`;
}

function formatPageResultCount(total: number) {
  return `${total.toLocaleString()} ${total === 1 ? 'result' : 'results'}`;
}
