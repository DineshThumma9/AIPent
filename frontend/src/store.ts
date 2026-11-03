import { create } from 'zustand'
import { persist } from 'zustand/middleware'

type SelectedState = {
  selectedId: number | null
  select: (id: number | null) => void
}

// Only the selection is persisted. Server data stays on the server.
export const useSelected = create<SelectedState>()(
  persist(
    (set) => ({
      selectedId: null,
      select: (selectedId) => set({ selectedId }),
    }),
    { name: 'aipent.selected' },
  ),
)
