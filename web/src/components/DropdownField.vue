<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";

type DropdownValue = string | number;
interface DropdownOption {
  value: DropdownValue;
  label: string;
  disabled?: boolean;
  badge?: string;
  icon?: string;
  iconAlt?: string;
  iconText?: string;
  searchText?: string;
}

const props = withDefaults(defineProps<{
  modelValue: DropdownValue;
  options: Array<DropdownOption | string>;
  theme: "light" | "dark";
  language?: "zh-CN" | "en";
  menuId: string;
  placeholder?: string;
  editable?: boolean;
  searchable?: boolean;
  required?: boolean;
  disabled?: boolean;
  menuNote?: string;
  triggerLabel?: string;
  menuPlacement?: "top" | "bottom";
}>(), {
  placeholder: "请选择",
  editable: false,
  searchable: false,
  required: false,
  disabled: false,
  menuNote: "",
  triggerLabel: "选项",
  menuPlacement: "bottom"
});

const emit = defineEmits<{
  "update:modelValue": [value: DropdownValue];
  change: [value: DropdownValue];
}>();
const root = ref<HTMLElement | null>(null);
const open = ref(false);
const query = ref("");
const normalizedOptions = computed<DropdownOption[]>(() => props.options.map(option =>
  typeof option === "string" ? { value: option, label: option } : option
));
const selectedOption = computed(() => normalizedOptions.value.find(option =>
  String(option.value) === String(props.modelValue)
));
const filteredOptions = computed(() => {
  const needle = query.value.trim().toLocaleLowerCase(props.language || undefined);
  if (!props.searchable || !needle) return normalizedOptions.value;
  return normalizedOptions.value.filter(option =>
    `${option.value} ${option.label} ${option.searchText || ""}`.toLocaleLowerCase(props.language || undefined).includes(needle)
  ).sort((left, right) => {
    const exact = (option: DropdownOption) => {
      const value = String(option.value).toLocaleLowerCase(props.language || undefined);
      const label = option.label.toLocaleLowerCase(props.language || undefined);
      return value === needle || label.endsWith(`· ${needle}`) ? 0 : 1;
    };
    return exact(left) - exact(right);
  });
});
const displayValue = computed(() => props.searchable
  ? open.value ? query.value : selectedOption.value?.label ?? ""
  : props.editable ? String(props.modelValue ?? "") : selectedOption.value?.label ?? ""
);

function updateValue(event: Event) {
  const value = (event.target as HTMLInputElement).value;
  if (props.searchable) {
    query.value = value;
    open.value = true;
  } else if (props.editable) {
    emit("update:modelValue", value);
  }
}

function choose(option: DropdownOption) {
  if (option.disabled) return;
  emit("update:modelValue", option.value);
  emit("change", option.value);
  query.value = "";
  open.value = false;
}

function toggle() {
  if (props.disabled) return;
  open.value = !open.value;
  if (open.value && props.searchable) query.value = "";
}

function openFromFocus() {
  if (!props.disabled && props.searchable) open.value = true;
}

function chooseFirstMatch(event: KeyboardEvent) {
  if (!props.searchable || !filteredOptions.value[0]) return;
  event.preventDefault();
  choose(filteredOptions.value[0]);
}

function closeFromOutside(event: PointerEvent) {
  if (!root.value?.contains(event.target as Node)) {
    query.value = "";
    open.value = false;
  }
}

watch(() => props.modelValue, () => { query.value = ""; });

onMounted(() => document.addEventListener("pointerdown", closeFromOutside));
onBeforeUnmount(() => document.removeEventListener("pointerdown", closeFromOutside));
</script>

<template>
  <div ref="root" class="dropdown-field" :class="[`theme-${theme}`, { disabled, 'has-icon': selectedOption?.icon || selectedOption?.iconText }]">
    <img v-if="selectedOption?.icon" class="dropdown-selected-icon" :src="selectedOption.icon" :alt="selectedOption.iconAlt || ''">
    <span v-else-if="selectedOption?.iconText" class="dropdown-selected-icon dropdown-selected-icon-text" role="img" :aria-label="selectedOption.iconAlt || ''">{{ selectedOption.iconText }}</span>
    <input
      :value="displayValue"
      :placeholder="placeholder"
      :readonly="!editable && !searchable"
      :required="required"
      :disabled="disabled"
      role="combobox"
      :aria-autocomplete="searchable ? 'list' : 'none'"
      :aria-expanded="open"
      :aria-controls="menuId"
      @input="updateValue"
      @focus="openFromFocus"
      @click="openFromFocus"
      @keydown.enter="chooseFirstMatch"
      @keydown.escape="query = ''; open = false"
      @keydown.down.prevent="open = true"
    >
    <button
      class="dropdown-trigger"
      :class="{ open }"
      type="button"
      :disabled="disabled"
      :aria-label="language === 'en' ? `${open ? 'Collapse' : 'Expand'} ${triggerLabel}` : `${open ? '收起' : '展开'}${triggerLabel}`"
      :aria-expanded="open"
      @click="toggle"
    >
      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 10 5 5 5-5" /></svg>
    </button>
    <div v-if="open" :id="menuId" class="dropdown-menu" :class="`placement-${menuPlacement}`" role="listbox">
      <button
        v-for="option in filteredOptions"
        :key="String(option.value)"
        class="dropdown-option"
        :class="{ selected: String(option.value) === String(modelValue) }"
        type="button"
        role="option"
        :data-value="String(option.value)"
        :disabled="option.disabled"
        :aria-selected="String(option.value) === String(modelValue)"
        @click="choose(option)"
      >
        <span class="dropdown-option-copy"><img v-if="option.icon" :src="option.icon" :alt="option.iconAlt || ''"><span v-else-if="option.iconText" class="dropdown-option-icon-text" role="img" :aria-label="option.iconAlt || ''">{{ option.iconText }}</span><span>{{ option.label }}</span></span><small v-if="option.badge">{{ option.badge }}</small>
      </button>
      <p v-if="searchable && !filteredOptions.length">{{ language === "en" ? "No matching country" : "未找到匹配的国家" }}</p>
      <p v-if="menuNote">{{ menuNote }}</p>
    </div>
  </div>
</template>

<style scoped>
.dropdown-field { position: relative; }
.dropdown-field input { padding-right: 58px; }
.dropdown-field.has-icon input { padding-left: 48px; }
.dropdown-selected-icon {
  position: absolute; top: 50%; left: 14px; z-index: 2; width: 25px; height: 17px;
  border-radius: 3px; object-fit: cover; transform: translateY(-50%); pointer-events: none;
}
.dropdown-selected-icon-text {
  display: grid; height: 25px; place-items: center; font-family: "Twemoji Country Flags", sans-serif;
  font-size: 23px; line-height: 1;
}
.dropdown-field input[readonly]:not(:disabled) { cursor: text; }
.dropdown-trigger {
  position: absolute;
  top: 50%;
  right: 8px;
  z-index: 2;
  display: grid;
  width: 36px;
  height: 36px;
  min-height: 0;
  padding: 0;
  place-items: center;
  color: #6366f1;
  border: 0;
  border-radius: 10px;
  background: transparent;
  box-shadow: none;
  transform: translateY(-50%);
  transition: color .18s, background .18s;
}
.dropdown-trigger:hover, .dropdown-trigger.open {
  color: #4338ca;
  background: #eef2ff;
}
.dropdown-trigger svg {
  width: 18px;
  height: 18px;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2;
  transition: transform .18s ease;
}
.dropdown-trigger.open svg { transform: rotate(180deg); }
.dropdown-menu {
  position: absolute;
  top: calc(100% + 7px);
  right: 0;
  left: 0;
  z-index: 20;
  max-height: min(420px, 50vh);
  overflow-y: auto;
  padding: 6px;
  border: 1px solid #dbe3ee;
  border-radius: 12px;
  background: #fff;
  box-shadow: 0 18px 45px rgba(71, 85, 105, .22);
}
.dropdown-menu.placement-top { top: auto; bottom: calc(100% + 7px); max-height: min(360px, 46vh); }
.dropdown-option {
  display: flex;
  width: 100%;
  min-height: 38px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 10px;
  color: #475569;
  border: 0;
  border-radius: 8px;
  background: transparent;
  text-align: left;
}
.dropdown-option-copy { display: flex; min-width: 0; align-items: center; gap: 9px; overflow-wrap: anywhere; }
.dropdown-option-copy img { width: 25px; height: 17px; flex: 0 0 auto; border-radius: 3px; object-fit: cover; }
.dropdown-option-icon-text { width: 25px; flex: 0 0 auto; font-family: "Twemoji Country Flags", sans-serif; font-size: 21px; line-height: 1; }
.dropdown-option-copy span { min-width: 0; }
.dropdown-option:hover, .dropdown-option.selected { color: #4338ca; background: #eef2ff; }
.dropdown-option:disabled { cursor: not-allowed; opacity: .45; }
.dropdown-option small { flex: none; padding: 3px 7px; color: #047857; border-radius: 999px; background: #d1fae5; }
.dropdown-menu p { margin: 5px 8px 3px; color: #94a3b8; font-size: 10px; font-weight: 500; }
.dropdown-field.disabled { opacity: .72; }
.theme-dark .dropdown-trigger {
  color: #a5b4fc;
  background: transparent;
  box-shadow: none;
}
.theme-dark .dropdown-trigger:hover, .theme-dark .dropdown-trigger.open {
  color: #e0e7ff;
  background: #283451;
}
.theme-dark .dropdown-menu { border-color: #334155; background: #111827; box-shadow: 0 18px 45px rgba(0, 0, 0, .4); }
.theme-dark .dropdown-option { color: #dbe7f5; }
.theme-dark .dropdown-option:hover, .theme-dark .dropdown-option.selected { color: #c7d2fe; background: #25314a; }
.theme-dark .dropdown-option small { color: #6ee7b7; background: #064e3b; }
</style>
