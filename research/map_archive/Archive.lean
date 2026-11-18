/- Fixed-weight enumerative coding for a predicted column. No hash assumption. -/
namespace MapArchive

-- The alphabet has b+1 symbols. A miss is numbered after removing the
-- predicted symbol from the alphabet, so there are only b miss digits.
def delta (p a : Nat) : Option Nat :=
  if a = p then none else some (if a < p then a else a - 1)

def restore (p : Nat) : Option Nat → Nat
  | none => p
  | some e => if e < p then e else e + 1

theorem restore_delta (p a : Nat) : restore p (delta p a) = a := by
  unfold delta
  split <;> rename_i h
  · simp [restore, h]
  · by_cases hlt : a < p
    · simp [restore, hlt]
    · have hn : ¬ a - 1 < p := by omega
      simp [restore, hlt, hn]; omega

theorem delta_restore (p : Nat) (e : Option Nat) : delta p (restore p e) = e := by
  cases e with
  | none => simp [restore, delta]
  | some e =>
    by_cases h : e < p
    · simp [restore, delta, h, Nat.ne_of_lt h]
    · have gt : p < e + 1 := by omega
      simp [restore, delta, h, Nat.ne_of_gt gt, Nat.not_lt_of_ge (Nat.le_of_lt gt)]

-- Size of the class of length-n residual words with exactly k misses.
def ways (b : Nat) : Nat → Nat → Nat
  | 0, 0 => 1
  | 0, _+1 => 0
  | _+1, 0 => 1
  | n+1, k+1 => ways b n (k+1) + b * ways b n k

def binom : Nat → Nat → Nat
  | 0, 0 => 1
  | 0, _+1 => 0
  | _+1, 0 => 1
  | n+1, k+1 => binom n (k+1) + binom n k

theorem ways_formula (b n k : Nat) : ways b n k = binom n k * b^k := by
  induction n generalizing k with
  | zero => cases k <;> simp [ways, binom]
  | succ n ih =>
    cases k with
    | zero => simp [ways, binom]
    | succ k =>
      rw [ways, binom, ih, ih, Nat.add_mul, Nat.pow_succ]
      ac_rfl

-- The byte codec uses the bit length of count-1, rounded up to a byte.
-- This is the least whole-byte width sufficient for all ranks, even at 1
-- and exact powers of 256. No floating-point logarithms are involved.
def byteWidth (count : Nat) : Nat :=
  let m := count - 1
  ((if m = 0 then 0 else m.log2 + 1) + 7) / 8

theorem byteWidth_le_iff (count t : Nat) (hc : 0 < count) :
    byteWidth count ≤ t ↔ count ≤ 256^t := by
  cases count with
  | zero => omega
  | succ m =>
    cases m with
    | zero => simp [byteWidth, Nat.one_le_pow]
    | succ u =>
      have hp : (256 : Nat)^t = 2^(8*t) := (Nat.pow_mul 2 8 t).symm
      have hl := Nat.log2_lt (n := u+1) (k := 8*t) (Nat.succ_ne_zero _)
      simp only [byteWidth, Nat.add_one_sub_one, Nat.add_one_ne_zero, ite_false, hp]
      omega

abbrev Word := List (Option Nat)

def weight : Word → Nat
  | [] => 0
  | none :: t => weight t
  | some _ :: t => weight t + 1

def valid (b : Nat) : Word → Prop
  | [] => True
  | none :: t => valid b t
  | some e :: t => e < b ∧ valid b t

def rank (b : Nat) : Word → Nat
  | [] => 0
  | none :: t => rank b t
  | some e :: t => ways b t.length (weight t + 1) + (rank b t + e * ways b t.length (weight t))

-- Same rank as the four-row wire vector in test_hmar.py.
example : rank 255 [none, some 187, none, none] = 697 := by decide

private theorem ways_mono (b n k : Nat) : ways b n k ≤ ways b (n+1) k := by
  cases k with
  | zero => cases n <;> simp [ways]
  | succ k => simp [ways]

theorem rank_lt (b : Nat) (xs : Word) (h : valid b xs) : rank b xs < ways b xs.length (weight xs) := by
  induction xs with
  | nil => exact Nat.zero_lt_one
  | cons x t ih =>
    cases x with
    | none => exact Nat.lt_of_lt_of_le (ih h) (ways_mono ..)
    | some e =>
      obtain ⟨he, ht⟩ := h
      have hr := ih ht
      have hm := Nat.mul_le_mul_right (ways b t.length (weight t)) he
      simp only [Nat.succ_mul] at hm
      simp only [rank, weight, List.length_cons, ways, Nat.add_lt_add_iff_left]
      omega

-- Only ranks in [0, ways b n k) are used; the byte decoder checks this.
def unrank (b : Nat) : Nat → Nat → Nat → Word
  | 0, _, _ => []
  | n+1, k, r =>
    let cut := ways b n k
    if r < cut then none :: unrank b n k r
    else
      let stride := ways b n (k-1)
      let u := r-cut
      some (u / stride) :: unrank b n (k-1) (u % stride)

theorem unrank_rank (b : Nat) (xs : Word) (h : valid b xs) :
    unrank b xs.length (weight xs) (rank b xs) = xs := by
  induction xs with
  | nil => rfl
  | cons x t ih =>
    cases x with
    | none => simp [weight, rank, unrank, rank_lt b t h, ih h]
    | some e =>
      have hr := rank_lt b t h.2
      have hs := Nat.zero_lt_of_lt hr
      simp [weight, rank, unrank, Nat.add_mul_div_right _ _ hs, Nat.div_eq_of_lt hr,
        Nat.mod_eq_of_lt hr, ih h.2]

-- Conversely there are no holes in the integer interval. Together with
-- unrank_rank this proves a bijection, not just a collision-free numbering.
theorem unrank_spec (b n k r : Nat) (hr : r < ways b n k) :
    let xs := unrank b n k r
    valid b xs ∧ xs.length = n ∧ weight xs = k ∧ rank b xs = r := by
  induction n generalizing k r with
  | zero =>
    cases k with
    | zero => have : r = 0 := by simpa [ways] using hr
              subst r; exact ⟨trivial, rfl, rfl, rfl⟩
    | succ k => simp [ways] at hr
  | succ n ih =>
    by_cases hit : r < ways b n k
    · obtain ⟨hv, hl, hw, he⟩ := ih k r hit
      simpa [unrank, hit, valid, weight, rank] using And.intro hv ⟨hl, hw, he⟩
    · cases k with
      | zero =>
        have hn : ways b n 0 = 1 := by cases n <;> rfl
        simp [ways, hn] at hit hr; omega
      | succ k =>
        let cut := ways b n (k+1)
        let stride := ways b n k
        have hcap : r < cut + b * stride := hr
        have hu : r - cut < b * stride := by dsimp [cut] at *; omega
        have hs : 0 < stride := by
          cases h : stride with
          | zero => simp [h] at hu
          | succ s => omega
        have digit : (r-cut)/stride < b := (Nat.div_lt_iff_lt_mul hs).mpr hu
        obtain ⟨hv, hl, hw, he⟩ := ih k ((r-cut)%stride) (Nat.mod_lt _ hs)
        have recover := Nat.mod_add_div (r-cut) stride
        rw [Nat.mul_comm stride] at recover
        simp only [unrank, ite_eq_right hit, Nat.add_sub_cancel, valid, List.length_cons,
          weight, rank]
        refine ⟨⟨digit, hv⟩, congrArg (· + 1) hl, congrArg (· + 1) hw, ?_⟩
        rw [hl, hw, he]
        change cut + ((r-cut)%stride + (r-cut)/stride * stride) = r
        rw [recover]
        exact Nat.add_sub_of_le (Nat.le_of_not_gt hit)

-- The ordered key list is side information. No sorting or injectivity of f.
def residuals {K : Type} (f : K → Nat) (rows : List (K × Nat)) : Word :=
  rows.map fun (x, a) => delta (f x) a

private theorem valid_residuals {K : Type} (b : Nat) (f : K → Nat) (rows : List (K × Nat))
    (h : ∀ row ∈ rows, f row.1 ≤ b ∧ row.2 ≤ b) : valid b (residuals f rows) := by
  induction rows with
  | nil => trivial
  | cons row t ih =>
    have ⟨hp, ha⟩ := h row (by simp)
    have ht := ih (fun r hr => h r (by simp [hr]))
    simp only [residuals, List.map_cons, delta]
    split
    · exact ht
    · exact ⟨by split <;> omega, ht⟩

def assemble {K : Type} (f : K → Nat) (keys : List K) (xs : Word) : List (K × Nat) :=
  List.zipWith (fun key e => (key, restore (f key) e)) keys xs

private theorem assemble_residuals {K : Type} (f : K → Nat) (rows : List (K × Nat)) :
    assemble f (rows.map Prod.fst) (residuals f rows) = rows := by
  induction rows with
  | nil => rfl
  | cons row t ih => simp [assemble, residuals, restore_delta] at ih ⊢

theorem block_roundtrip {K : Type} (b : Nat) (f : K → Nat) (rows : List (K × Nat))
    (h : ∀ row ∈ rows, f row.1 ≤ b ∧ row.2 ≤ b) :
    let xs := residuals f rows
    let keys := rows.map Prod.fst
    assemble f keys (unrank b keys.length (weight xs) (rank b xs)) = rows := by
  dsimp only
  have len : (rows.map Prod.fst).length = (residuals f rows).length := by simp [residuals]
  rw [len, unrank_rank b _ (valid_residuals b f rows h), assemble_residuals]

-- Optional key predictor: copy a prefix of the previous key, store the suffix.
def shared [DecidableEq A] : List A → List A → Nat
  | a :: p, b :: x => if a = b then shared p x + 1 else 0
  | _, _ => 0

theorem prefix_split [DecidableEq A] (p x : List A) :
    p.take (shared p x) ++ x.drop (shared p x) = x := by
  induction p generalizing x with
  | nil => cases x <;> rfl
  | cons a p ih =>
    cases x with
    | nil => rfl
    | cons b x => by_cases h : a = b <;> simp [shared, h, ih]

def splitKeys [DecidableEq A] (prev : List A) : List (List A) → List (Nat × List A)
  | [] => []
  | x :: xs => let l := shared prev x
               (l, x.drop l) :: splitKeys x xs

def joinKeys (prev : List A) : List (Nat × List A) → List (List A)
  | [] => []
  | (l, tail) :: ts => let x := prev.take l ++ tail
                       x :: joinKeys x ts

theorem keys_roundtrip [DecidableEq A] (prev : List A) (keys : List (List A)) :
    joinKeys prev (splitKeys prev keys) = keys := by
  induction keys generalizing prev with
  | nil => rfl
  | cons x xs ih => simp only [splitKeys, joinKeys, prefix_split, ih]

end MapArchive
