import Std

/-!
# RSM1: machine-checked mathematical core

Byte strings are lists in this model. The proofs are parametric in the byte
alphabet. They are not an extraction or verification of the Python parser.
Lean 4.19.0, standard library only.
-/

set_option autoImplicit false
namespace RSM
universe u v w

section Front
variable {A : Type u} [DecidableEq A]

def lcp : List A → List A → Nat
  | a :: as, b :: bs => if a = b then lcp as bs + 1 else 0
  | _, _ => 0

theorem lcp_agrees (a b : List A) : a.take (lcp a b) = b.take (lcp a b) := by
  induction a generalizing b with
  | nil => simp [lcp]
  | cons x xs ih =>
    cases b with
    | nil => simp [lcp]
    | cons y ys =>
      by_cases h : x = y
      · subst y
        simp [lcp, ih ys]
      · simp [lcp, h]

def frontEncode (prev : List A) : List (List A) → List (Nat × List A)
  | [] => []
  | key :: keys =>
      let p := lcp prev key
      (p, key.drop p) :: frontEncode key keys

def frontDecode (prev : List A) : List (Nat × List A) → List (List A)
  | [] => []
  | (p, suffix) :: rows =>
      let key := prev.take p ++ suffix
      key :: frontDecode key rows

theorem front_roundtrip (prev : List A) (keys : List (List A)) :
    frontDecode prev (frontEncode prev keys) = keys := by
  induction keys generalizing prev with
  | nil => rfl
  | cons key keys ih =>
    simp only [frontEncode, frontDecode]
    rw [lcp_agrees prev key, List.take_append_drop, ih]
end Front

section Frame
variable {A : Type u}

def unchunk (sizes : List Nat) (stream : List A) : List (List A) × List A :=
  match sizes with
  | [] => ([], stream)
  | n :: ns =>
      let (pieces, tail) := unchunk ns (stream.drop n)
      (stream.take n :: pieces, tail)

theorem chunks_roundtrip (fields : List (List A)) (tail : List A) :
    unchunk (fields.map List.length) (fields.flatten ++ tail) = (fields, tail) := by
  induction fields with
  | nil => rfl
  | cons a fields ih =>
    simp only [List.map_cons, List.flatten_cons, List.append_assoc, unchunk]
    rw [List.drop_left, List.take_left, ih]
end Frame

section Predictor
variable {K : Type u} {V : Type v}

structure Sparse (K : Type u) (V : Type v) where
  keys : List K
  isException : List Bool
  literals : List V

def predPack [DecidableEq V] (predict : K → V) : List (K × V) → Sparse K V
  | [] => ⟨[], [], []⟩
  | (k, v) :: rows =>
      let rest := predPack predict rows
      if v = predict k then
        ⟨k :: rest.keys, false :: rest.isException, rest.literals⟩
      else
        ⟨k :: rest.keys, true :: rest.isException, v :: rest.literals⟩

def predRead (predict : K → V) :
    List K → List Bool → List V → Option (List (K × V))
  | [], [], [] => some []
  | k :: ks, false :: flags, vs => (predRead predict ks flags vs).map ((k, predict k) :: ·)
  | k :: ks, true :: flags, v :: vs => (predRead predict ks flags vs).map ((k, v) :: ·)
  | _, _, _ => none

theorem pred_roundtrip [DecidableEq V] (predict : K → V) (rows : List (K × V)) :
    let enc := predPack predict rows
    predRead predict enc.keys enc.isException enc.literals = some rows := by
  induction rows with
  | nil => rfl
  | cons row rows ih =>
    rcases row with ⟨k, v⟩
    by_cases h : v = predict k
    · simp [predPack, h, predRead, ih]
    · simp [predPack, h, predRead, ih]

/-- An end-to-end structured record model, keeping the value column in lockstep. -/
structure Structured (A : Type u) (V : Type v) (C : Type w) where
  keys : List (Nat × List A)
  values : List V
  exceptions : List Bool
  overrides : List C

def structuredPack {A : Type u} {C : Type w} [DecidableEq A] [DecidableEq C]
    (predict : List A → C) (rows : List (List A × (V × C))) : Structured A V C :=
  let residual := predPack predict (rows.map fun r => (r.1, r.2.2))
  ⟨frontEncode [] residual.keys, rows.map (fun r => r.2.1), residual.isException, residual.literals⟩

def structuredRead {A : Type u} {C : Type w} (predict : List A → C)
    (enc : Structured A V C) : Option (List (List A × (V × C))) :=
  match predRead predict (frontDecode [] enc.keys) enc.exceptions enc.overrides with
  | none => none
  | some rows => some (List.zipWith (fun (k, c) v => (k, (v, c))) rows enc.values)

theorem structured_roundtrip {A : Type u} {C : Type w} [DecidableEq A] [DecidableEq C]
    (predict : List A → C) (rows : List (List A × (V × C))) :
    structuredRead predict (structuredPack predict rows) = some rows := by
  simp only [structuredRead, structuredPack, front_roundtrip, pred_roundtrip]
  congr 1
  induction rows with
  | nil => rfl
  | cons a rows ih =>
    obtain ⟨k, v, c⟩ := a
    simp [List.zipWith, ih]
end Predictor

-- Shared unary-gap representation for the high quotients and the exception bitmap.
def gapBits (gap : Nat) (tail : List Bool) : List Bool := List.replicate gap false ++ true :: tail

def readGap : List Bool → Option (Nat × List Bool)
  | [] => none
  | true :: bs => some (0, bs)
  | false :: bs => (readGap bs).map fun (g, rest) => (g + 1, rest)

theorem gap_roundtrip (gap : Nat) (tail : List Bool) :
    readGap (gapBits gap tail) = some (gap, tail) := by
  induction gap with
  | zero => rfl
  | succ g ih =>
    simpa only [gapBits, List.replicate_succ, List.cons_append, readGap, Option.map_some] using
      congrArg (Option.map (fun (g, rest) => (g + 1, rest))) ih

def maskGaps : List Bool → List Nat × Nat
  | [] => ([], 0)
  | true :: bs =>
      let (gs, z) := maskGaps bs
      (0 :: gs, z)
  | false :: bs =>
      match maskGaps bs with
      | ([], z) => ([], z + 1)
      | (g :: gs, z) => ((g + 1) :: gs, z)

def fromGaps (gs : List Nat) (trailing : Nat) : List Bool :=
  match gs with
  | [] => List.replicate trailing false
  | g :: gs => gapBits g (fromGaps gs trailing)

theorem sparse_mask_roundtrip (mask : List Bool) :
    fromGaps (maskGaps mask).1 (maskGaps mask).2 = mask := by
  induction mask with
  | nil => rfl
  | cons b bs ih =>
    cases he : maskGaps bs with
    | mk gs z =>
      rw [he] at ih
      cases b with
      | false =>
        cases gs with
        | nil =>
          change fromGaps [] z = bs at ih
          simp only [maskGaps, he, Prod.fst, Prod.snd, fromGaps, List.replicate_succ]
          rw [← ih]
          rfl
        | cons g gs =>
          change fromGaps (g :: gs) z = bs at ih
          simp only [maskGaps, he, Prod.fst, Prod.snd]
          rw [← ih]
          simp [fromGaps, gapBits, List.replicate_succ]
      | true =>
        change fromGaps gs z = bs at ih
        simp [maskGaps, he, fromGaps, gapBits, ih]

def orderedFrom (prev : Nat) : List Nat → Prop
  | [] => True
  | x :: xs => prev ≤ x ∧ orderedFrom x xs

def packHigh (prev : Nat) : List Nat → List Bool
  | [] => []
  | x :: xs => gapBits (x - prev) (packHigh x xs)

def unpackHigh : Nat → Nat → List Bool → Option (List Nat × List Bool)
  | 0, _, bits => some ([], bits)
  | n + 1, prev, bits => do
      let (gap, afterGap) ← readGap bits
      let x := prev + gap
      let (xs, rest) ← unpackHigh n x afterGap
      return (x :: xs, rest)

theorem high_roundtrip (xs : List Nat) (prev : Nat) (h : orderedFrom prev xs)
    (tail : List Bool) : unpackHigh xs.length prev (packHigh prev xs ++ tail) = some (xs, tail) := by
  induction xs generalizing prev with
  | nil => rfl
  | cons x xs ih =>
    have h' : prev ≤ x ∧ orderedFrom x xs := h
    have add : prev + (x - prev) = x := by omega
    simp only [List.length_cons, packHigh, unpackHigh]
    rw [show gapBits (x - prev) (packHigh x xs) ++ tail =
      gapBits (x - prev) (packHigh x xs ++ tail) by simp [gapBits, List.append_assoc]]
    simp [gap_roundtrip, add, ih x h'.2]

theorem last_ge (xs : List Nat) (prev : Nat) (h : orderedFrom prev xs) :
    prev ≤ xs.getLastD prev := by
  induction xs generalizing prev with
  | nil => exact Nat.le_refl _
  | cons x xs ih =>
    have h' : prev ≤ x ∧ orderedFrom x xs := h
    rw [List.getLastD_cons]
    exact Nat.le_trans h'.1 (ih x h'.2)

theorem high_length (xs : List Nat) (prev : Nat) (h : orderedFrom prev xs) :
    (packHigh prev xs).length = xs.length + (xs.getLastD prev - prev) := by
  induction xs generalizing prev with
  | nil => simp [packHigh, List.getLastD_nil]
  | cons x xs ih =>
    have h' : prev ≤ x ∧ orderedFrom x xs := h
    have hlast := last_ge xs x h'.2
    simp only [packHigh, gapBits, List.length_append, List.length_replicate,
      List.length_cons, List.getLastD_cons, ih x h'.2]
    omega

theorem ordered_div (xs : List Nat) (prev radix : Nat) (h : orderedFrom prev xs)
    (hp : 0 < radix) : orderedFrom (prev / radix) (xs.map (· / radix)) := by
  induction xs generalizing prev with
  | nil => trivial
  | cons x xs ih =>
    have h' : prev ≤ x ∧ orderedFrom x xs := h
    change prev / radix ≤ x / radix ∧ orderedFrom (x / radix) (xs.map (· / radix))
    have hx : x ≤ x / radix * radix + radix - 1 :=
      (Nat.div_le_iff_le_mul hp).mp (Nat.le_refl _)
    exact ⟨(Nat.div_le_iff_le_mul hp).mpr (Nat.le_trans h'.1 hx), ih x h'.2⟩

def efPack (radix : Nat) (xs : List Nat) : List Nat × List Bool :=
  (xs.map (· % radix), packHigh 0 (xs.map (· / radix)))

def efRead (radix : Nat) (lo : List Nat) (highBits : List Bool) : Option (List Nat × List Bool) :=
  match unpackHigh lo.length 0 highBits with
  | none => none
  | some (hi, tail) => some (List.zipWith (fun h l => radix * h + l) hi lo, tail)

theorem join_quotients (xs : List Nat) (radix : Nat) :
    List.zipWith (fun h l => radix * h + l) (xs.map (· / radix)) (xs.map (· % radix)) = xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp [List.zipWith, Nat.div_add_mod, ih]

theorem ef_roundtrip (xs : List Nat) (radix : Nat) (hp : 0 < radix) (h : orderedFrom 0 xs)
    (tail : List Bool) :
    efRead radix (efPack radix xs).1 ((efPack radix xs).2 ++ tail) = some (xs, tail) := by
  have mono : orderedFrom 0 (xs.map (· / radix)) := by simpa using ordered_div xs 0 radix h hp
  have length_eq : (xs.map (· % radix)).length = (xs.map (· / radix)).length := by simp
  simp only [efRead, efPack, length_eq, high_roundtrip _ 0 mono tail, join_quotients]

/-- High bit count, excluding byte padding and the fixed-width low parts. -/
theorem ef_high_length (xs : List Nat) (radix : Nat) (hp : 0 < radix) (h : orderedFrom 0 xs) :
    (efPack radix xs).2.length = xs.length + xs.getLastD 0 / radix := by
  have mono : orderedFrom 0 (xs.map (· / radix)) := by simpa using ordered_div xs 0 radix h hp
  change (packHigh 0 (xs.map (· / radix))).length = _
  rw [high_length _ 0 mono, List.length_map, Nat.sub_zero]
  exact congrArg (xs.length + ·) (by simpa using (List.getLastD_map (f := (· / radix)) (l := xs) (a := 0)))

section Prefix
variable {A : Type u}

inductive CodeTree (A : Type u) where
  | dead
  | leaf (value : A)
  | branch (left right : CodeTree A)

def readOne : CodeTree A → List Bool → Option (A × List Bool)
  | .dead, _ => none
  | .leaf a, bits => some (a, bits)
  | .branch l _, false :: bits => readOne l bits
  | .branch _ r, true :: bits => readOne r bits
  | .branch _ _, [] => none

inductive At : CodeTree A → A → List Bool → Prop where
  | leaf (a : A) : At (.leaf a) a []
  | left {l r : CodeTree A} {a : A} {bits : List Bool} : At l a bits → At (.branch l r) a (false :: bits)
  | right {l r : CodeTree A} {a : A} {bits : List Bool} : At r a bits → At (.branch l r) a (true :: bits)

theorem read_one_exact {t : CodeTree A} {a : A} {code : List Bool} (h : At t a code)
    (tail : List Bool) : readOne t (code ++ tail) = some (a, tail) := by
  induction h <;> simp [readOne, *]

def readBytes (t : CodeTree (List A)) (need : Nat) (stream : List Bool) :
    Option (List A × List Bool) :=
  match need with
  | 0 => some ([], stream)
  | n + 1 =>
    match readOne t stream with
    | none => none
    | some (token, rest) =>
      if h : 0 < token.length ∧ token.length ≤ n + 1 then
        (readBytes t (n + 1 - token.length) rest).map fun (xs, tail) => (token ++ xs, tail)
      else none
termination_by need
decreasing_by omega

theorem read_bytes_step (t : CodeTree (List A)) (need : Nat) (stream : List Bool)
    (token : List A) (rest : List Bool) (h : readOne t stream = some (token, rest))
    (hn : 0 < token.length) (hl : token.length ≤ need) :
    readBytes t need stream =
      (readBytes t (need - token.length) rest).map fun (xs, tail) => (token ++ xs, tail) := by
  cases need with
  | zero => omega
  | succ n => rw [readBytes]; simp [h, hn, hl]

def emit (code : List A → List Bool) : List (List A) → List Bool
  | [] => []
  | t :: ts => code t ++ emit code ts

theorem tokens_roundtrip (t : CodeTree (List A)) (code : List A → List Bool)
    (tokens : List (List A))
    (valid : ∀ a ∈ tokens, 0 < a.length ∧ At t a (code a)) (tail : List Bool) :
    readBytes t tokens.flatten.length (emit code tokens ++ tail) = some (tokens.flatten, tail) := by
  induction tokens with
  | nil => simp [emit, readBytes]
  | cons a tokens ih =>
    have ha := valid a (by simp)
    have hs : ∀ x ∈ tokens, 0 < List.length x ∧ At t x (code x) :=
      fun x hx => valid x (List.mem_cons_of_mem _ hx)
    simp only [List.flatten_cons, List.length_append, emit, List.append_assoc]
    rw [read_bytes_step t _ _ a (emit code tokens ++ tail) (read_one_exact ha.2 _) ha.1 (by omega)]
    rw [show a.length + tokens.flatten.length - a.length = tokens.flatten.length by omega, ih hs]
    rfl
/-- The Python lane writes one token stream but stores each field's byte length. -/
theorem tokenized_fields_roundtrip (t : CodeTree (List A)) (code : List A → List Bool)
    (parses : List (List (List A)))
    (valid : ∀ a ∈ parses.flatten, 0 < a.length ∧ At t a (code a)) (tail : List Bool) :
    let fields := parses.map List.flatten
    (readBytes t fields.flatten.length (emit code parses.flatten ++ tail)).map
        (fun (bytes, rest) => ((unchunk (fields.map List.length) bytes).1, rest)) =
      some (fields, tail) := by
  dsimp only
  have dec := tokens_roundtrip t code parses.flatten valid tail
  rw [List.flatten_flatten] at dec
  rw [dec]
  have split := chunks_roundtrip (parses.map List.flatten) ([] : List A)
  simp only [List.append_nil] at split
  change some ((unchunk ((parses.map List.flatten).map List.length)
    (parses.map List.flatten).flatten).1, tail) = _
  rw [split]

end Prefix

/-- The min routine also certifies that an admitted raw candidate bounds the answer. -/
def least : List Nat → Option Nat
  | [] => none
  | a :: as => some (match least as with | none => a | some b => min a b)

theorem least_exact (xs : List Nat) (n : Nat) (h : least xs = some n) :
    n ∈ xs ∧ ∀ c ∈ xs, n ≤ c := by
  induction xs generalizing n with
  | nil => simp [least] at h
  | cons a as ih =>
    cases he : least as with
    | none =>
      have empty : as = [] := by cases as <;> simp_all [least]
      subst as
      simp [least] at h
      subst n
      simp
    | some b =>
      have hb := ih b he
      simp only [least, he, Option.some.injEq] at h
      subst n
      constructor
      · by_cases hle : a ≤ b
        · simp [Nat.min_eq_left hle]
        · rw [Nat.min_eq_right (by omega : b ≤ a)]
          exact List.mem_cons_of_mem _ hb.1
      · intro c hc
        rcases List.mem_cons.mp hc with heq | mem
        · subst c
          exact Nat.min_le_left a b
        · exact Nat.le_trans (Nat.min_le_right a b) (hb.2 c mem)

structure Edge where
  dst : Nat
  cost : Nat
  deriving DecidableEq, Repr

/-- Coordinates are the number of bytes remaining, so edges move downward. -/
inductive Route (edges : Nat → List Edge) : Nat → Nat → Prop where
  | stop : Route edges 0 0
  | hop {here c : Nat} {e : Edge} :
      e ∈ edges here → e.dst < here → Route edges e.dst c → Route edges here (e.cost + c)

/-- Any backward DP table satisfying the local recurrence gives an attained optimum. -/
theorem bellman_exact (edges : Nat → List Edge) (d : Nat → Nat) (base : d 0 = 0)
    (down : ∀ i, 0 < i → ∀ e ∈ edges i, e.dst < i)
    (step : ∀ i, 0 < i → least ((edges i).map (fun e => e.cost + d e.dst)) = some (d i))
    (i : Nat) : Route edges i (d i) ∧ ∀ c, Route edges i c → d i ≤ c := by
  have lower : ∀ {j c}, Route edges j c → d j ≤ c := by
    intro j c r
    induction r with
    | stop => simp [base]
    | @hop here c e hm he route ih =>
      have pos : 0 < here := by omega
      have mem : e.cost + d e.dst ∈ (edges here).map (fun e => e.cost + d e.dst) :=
        List.mem_map.mpr ⟨e, hm, rfl⟩
      have le := (least_exact _ _ (step here pos)).2 _ mem
      omega
  refine ⟨?_, fun _ r => lower r⟩
  induction i using Nat.strongRecOn with
  | ind here ih =>
    by_cases hz : here = 0
    · subst here
      rw [base]
      exact Route.stop
    · have pos : 0 < here := by omega
      have hm := (least_exact _ _ (step here pos)).1
      obtain ⟨e, mem, value⟩ := List.mem_map.mp hm
      have hd := down here pos e mem
      rw [← value]
      exact Route.hop mem hd (ih e.dst hd)

theorem raw_fallback (sizes : List Nat) (selected raw : Nat) (candidate : raw ∈ sizes)
    (result : least sizes = some selected) : selected ≤ raw :=
  (least_exact _ _ result).2 _ candidate

theorem no_collision_of_roundtrip {A : Type u} {B : Type v} (encode : A → B) (decode : B → Option A)
    (h : ∀ a, decode (encode a) = some a) (a b : A) (same : encode a = encode b) : a = b := by
  have he := congrArg decode same
  rw [h a, h b] at he
  exact Option.some.inj he

section Counting
-- We count arbitrary framed bit strings, not just prefix-free codes.
def fixedBits : Nat → List (List Bool)
  | 0 => [[]]
  | n + 1 => (fixedBits n).map (false :: ·) ++ (fixedBits n).map (true :: ·)

def shorterBits : Nat → List (List Bool)
  | 0 => []
  | n + 1 => fixedBits n ++ shorterBits n

theorem fixed_mem (n : Nat) (s : List Bool) : s ∈ fixedBits n ↔ s.length = n := by
  induction n generalizing s with
  | zero => simp [fixedBits]
  | succ n ih =>
    cases s with
    | nil => simp [fixedBits]
    | cons b s => cases b <;> simp [fixedBits, ih]

theorem shorter_contains (n : Nat) (s : List Bool) (h : s.length < n) : s ∈ shorterBits n := by
  induction n with
  | zero => omega
  | succ n ih =>
    rw [shorterBits, List.mem_append]
    by_cases he : s.length = n
    · exact Or.inl ((fixed_mem n s).mpr he)
    · exact Or.inr (ih (by omega))

theorem fixed_length (n : Nat) : (fixedBits n).length = 2 ^ n := by
  induction n with
  | zero => rfl
  | succ n ih => simp [fixedBits, ih, Nat.pow_succ, Nat.mul_two]

theorem shorter_length (n : Nat) : (shorterBits n).length + 1 = 2 ^ n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [shorterBits, List.length_append, fixed_length, Nat.pow_succ]
    omega

theorem nodup_map_injective {A : Type u} {B : Type v} (f : A → B)
    (inj : ∀ a b, f a = f b → a = b) (xs : List A) (h : xs.Nodup) : (xs.map f).Nodup :=
  List.Pairwise.map f (fun a b ne same => ne (inj a b same)) h

theorem fixed_nodup (n : Nat) : (fixedBits n).Nodup := by
  induction n with
  | zero => simp [fixedBits]
  | succ n ih =>
    change List.Nodup ((fixedBits n).map (false :: ·) ++ (fixedBits n).map (true :: ·))
    unfold List.Nodup
    rw [List.pairwise_append]
    refine ⟨nodup_map_injective _ (fun _ _ hh => (List.cons.inj hh).2) _ ih,
      nodup_map_injective _ (fun _ _ hh => (List.cons.inj hh).2) _ ih, ?_⟩
    intro a ma b mb
    obtain ⟨aa, _, rfl⟩ := List.mem_map.mp ma
    obtain ⟨bb, _, rfl⟩ := List.mem_map.mp mb
    simp

theorem finite_list_bound {A : Type u} [BEq A] [LawfulBEq A] (xs ys : List A) (nd : xs.Nodup)
    (sub : ∀ x ∈ xs, x ∈ ys) : xs.length ≤ ys.length := by
  induction xs generalizing ys with
  | nil => simp
  | cons x xs ih =>
    obtain ⟨notx, nTail⟩ := List.nodup_cons.mp nd
    have hx : x ∈ ys := sub x (by simp)
    have inside : ∀ z ∈ xs, z ∈ ys.erase x := by
      intro z hz
      have hne : z ≠ x := by intro h; subst z; exact notx hz
      exact (List.mem_erase_of_ne hne).mpr (sub z (List.mem_cons_of_mem _ hz))
    have smaller := ih (ys.erase x) nTail inside
    rw [List.length_erase_of_mem hx] at smaller
    have pos := List.length_pos_of_mem hx
    simp only [List.length_cons]
    omega

/-- No lossless encoder can make *every* length-n bit string shorter than n bits,
    even if variable-length outputs are allowed and their boundaries are known. -/
theorem not_all_shorten (n : Nat) (encode : List Bool → List Bool)
    (decode : List Bool → Option (List Bool)) (h : ∀ s, decode (encode s) = some s) :
    ¬ (∀ s, s.length = n → (encode s).length < n) := by
  intro all
  have nd := nodup_map_injective encode (no_collision_of_roundtrip encode decode h) _ (fixed_nodup n)
  have sub : ∀ t ∈ (fixedBits n).map encode, t ∈ shorterBits n := by
    intro t ht
    obtain ⟨s, hs, rfl⟩ := List.mem_map.mp ht
    exact shorter_contains n _ (all s ((fixed_mem n s).mp hs))
  have le := finite_list_bound _ _ nd sub
  rw [List.length_map, fixed_length] at le
  have count := shorter_length n
  omega
end Counting

end RSM

#print axioms RSM.front_roundtrip
#print axioms RSM.chunks_roundtrip
#print axioms RSM.pred_roundtrip
#print axioms RSM.structured_roundtrip
#print axioms RSM.sparse_mask_roundtrip
#print axioms RSM.ef_roundtrip
#print axioms RSM.ef_high_length
#print axioms RSM.tokens_roundtrip
#print axioms RSM.bellman_exact
#print axioms RSM.raw_fallback
#print axioms RSM.no_collision_of_roundtrip
#print axioms RSM.tokenized_fields_roundtrip
#print axioms RSM.not_all_shorten
