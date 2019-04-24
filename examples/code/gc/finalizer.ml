open Core.Std
open Async.Std

let attach_finalizer n v =
  match Heap_block.create v with
  | None -> printf "%20s: FAIL\n%!" n
  | Some hb ->
    let final _ = printf "%20s: OK\n%!" n in
    Gc.add_finalizer hb final

type t = { foo: bool }

let main () =
  let alloced_float = Unix.gettimeofday () in
  let alloced_bool = alloced_float > 0.0 in
  let alloced_string = String.create 4 in
  attach_finalizer "immediate int" 1;
  attach_finalizer "immediate float" 1.0;
  attach_finalizer "immediate variant" (`Foo "hello");
  attach_finalizer "immediate string" "hello world";
  attach_finalizer "immediate record" { foo=false };
  attach_finalizer "allocated float" alloced_float;
  attach_finalizer "allocated bool" alloced_bool;
  attach_finalizer "allocated variant" (`Foo alloced_bool);
  attach_finalizer "allocated string" alloced_string;
  attach_finalizer "allocated record" { foo=alloced_bool };
  Gc.compact ();
  return ()

let () =
  Command.async_basic ~summary:"Testing finalizers"
    Command.Spec.empty main
  |> Command.run
