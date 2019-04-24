open Ocamlbuild_plugin;;
open Ocamlbuild_pack;;

let ctypes_libdir = Sys.getenv "CTYPES_LIB_DIR" in
let ocaml_libdir = Sys.getenv "OCAML_LIB_DIR" in

dispatch begin
  function
  | After_rules ->

    rule "cstubs: lib_gen/x_types_detect.c -> x_types_detect"
      ~prods:["lib_gen/%_types_detect"]
      ~deps:["lib_gen/%_types_detect.c"]
      (fun env build ->
         Cmd (S[A"cc";
                A("-I"); A ctypes_libdir;
                A("-I"); A ocaml_libdir;
                A"-o";
                A(env "lib_gen/%_types_detect");
                A(env "lib_gen/%_types_detect.c");
               ]));

    rule "cstubs: lib_gen/x_types_detect -> lib/x_types_detected.ml"
      ~prods:["lib/%_types_detected.ml"]
      ~deps:["lib_gen/%_types_detect"]
      (fun env build ->
         Cmd (S[A(env "lib_gen/%_types_detect");
                Sh">";
                A(env "lib/%_types_detected.ml");
               ]));

    rule "cstubs: lib_gen/x_types.ml -> x_types_detect.c"
      ~prods:["lib_gen/%_types_detect.c"]
      ~deps: ["lib_gen/%_typegen.byte"]
      (fun env build ->
         Cmd (A(env "lib_gen/%_typegen.byte")));

    copy_rule "cstubs: lib_gen/x_types.ml -> lib/x_types.ml"
      "lib_gen/%_types.ml" "lib/%_types.ml";

    rule "cstubs: lib/x_bindings.ml -> x_stubs.c, x_stubs.ml"
      ~prods:["lib/%_stubs.c"; "lib/%_generated.ml"]
      ~deps: ["lib_gen/%_bindgen.byte"]
      (fun env build ->
        Cmd (A(env "lib_gen/%_bindgen.byte")));

    copy_rule "cstubs: lib_gen/x_bindings.ml -> lib/x_bindings.ml"
      "lib_gen/%_bindings.ml" "lib/%_bindings.ml";

    flag ["c"; "compile"] & S[A"-ccopt"; A"-I/usr/local/include"];
    flag ["c"; "ocamlmklib"] & A"-L/usr/local/lib";
    flag ["ocaml"; "link"; "native"; "program"] &
      S[A"-cclib"; A"-L/usr/local/lib"];

    (* Linking cstubs *)
    flag ["c"; "compile"; "use_ctypes"] & S[A"-I"; A ctypes_libdir];
    flag ["c"; "compile"; "debug"] & A"-g";

    (* Linking sodium *)
    flag ["c"; "compile"; "use_sodium"] &
      S[A"-ccopt"; A"--std=c99 -Wall -pedantic -Werror -Wno-pointer-sign"];
    flag ["c"; "ocamlmklib"; "use_sodium"] & A"-lsodium";

    (* Linking generated stubs *)
    dep ["ocaml"; "link"; "byte"; "library"; "use_sodium_stubs"]
      ["lib/dllsodium_stubs"-.-(!Options.ext_dll)];
    flag ["ocaml"; "link"; "byte"; "library"; "use_sodium_stubs"] &
      S[A"-dllib"; A"-lsodium_stubs"];

    dep ["ocaml"; "link"; "native"; "library"; "use_sodium_stubs"]
      ["lib/libsodium_stubs"-.-(!Options.ext_lib)];
    flag ["ocaml"; "link"; "native"; "library"; "use_sodium_stubs"] &
      S[A"-cclib"; A"-lsodium_stubs"; A"-cclib"; A"-lsodium"];

    (* Linking tests *)
    flag ["ocaml"; "link"; "byte"; "program"; "use_sodium_stubs"] &
      S[A"-dllib"; A"-lsodium_stubs"];
    dep ["ocaml"; "link"; "native"; "program"; "use_sodium_stubs"]
      ["lib/libsodium_stubs"-.-(!Options.ext_lib)];
    flag ["ocaml"; "link"; "native"; "program"; "use_sodium_stubs"] &
      S[A"-cclib"; A"-lsodium"];

  | _ -> ()
end;;
