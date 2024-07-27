(defn- codeblock
  "Inline code or codeblock"
  [lang &opt source]
  (def source2 (or source lang))
  (def lang2 (if source lang nil))
  (def highlighter (if lang2 (require (string lang2 ".syntax"))))
  {:tag "pre"
   "class" "mendoza-codeblock"
   :content {:tag "code"
             :content source2
             :language highlighter
             "data-language" lang2}})

(def- docstring-peg-source
  "Convert a docstring into a dom node."
  ~{:ws (set " \t\r\n\0\f")
    :funcdef (* (any :ws)
                (/ '(* "(" (any (if-not ")" 1)) ")")
                   ,|(codeblock "janet" $))
                "\n\n")
    :br (* "\n\n" (constant {:tag "br" :no-close true}))
    :li (* "\t" (/ '(any (if-not "\n" 1)) ,|{:tag "li" :content $}))
    :ul (* (some :li) (+ "\n" -1))
    :sent '(some (if-not "\n" 1))
    :main (* (? :funcdef) (/ (group (any (+ :ul :sent :br "\n"))) ,|{:tag "p" :content $}))})

(def- docstring-peg (peg/compile docstring-peg-source))

(defn- emit-item
  "Generate documentation for one entry."
  [key env-entry]
  (let [{:macro macro
         :value val
         :ref ref
         :source-map sm
         :doc docstring} env-entry
        real-val (if ref (get ref 0) val)
        binding-type (cond
                       macro :macro
                       ref (string :var " (" (type real-val) ")")
                       (type val))
        full-binding-type (cond
                            macro binding-type
                            (and (nil? real-val) (not ref)) binding-type
                            (function? real-val) binding-type
                            (cfunction? real-val) binding-type
                            (and (bytes? real-val) (< 35 (length real-val))) binding-type
                            [binding-type " " {:tag "code" "class" "binding-realval" :content (describe real-val)}])
        source-ref (if-let [[path line col] sm]
                     {:tag "div" "class" "source-map" :content (string path " at line " line ", column " col)}
                     "")
        doc2 (or docstring "")
        doc-dom (peg/match docstring-peg doc2)]
    {:tag "div" "class" "docstring" :content
     [{:tag "div" "class" "binding-wrap"
       :content [{:tag "span" "class" "binding" :content {:tag "a" "id" key :content (string key)}}
                 {:tag "span" "class" "binding-type" :content full-binding-type}
                 source-ref]}
      doc-dom]}))

(defn api-docs-group
  "Generate docs for a given module. Returns a node."
  [module func-list-str]
  (def func-list (string/split " " func-list-str))
  (def env (if (string? module) (require module) module))
  (seq [[k entry]
        :in (sort (pairs env))
        :when (symbol? k)
        :when (has-value? func-list (string k))
        :when (and (get entry :doc) (not (get entry :private)))]
    (emit-item k entry)))

(defn api-index-group
  "Generate an indexes for the given docs."
  [module func-list-str]
  (def func-list (string/split " " func-list-str))
  (def env (if (string? module) (require module) module))
  (def items (seq [[k entry]
                   :in (sort (pairs env))
                   :when (symbol? k)
                   :when (has-value? func-list (string k))
                   :when (and (get entry :doc) (not (get entry :private)))]
               {:tag "a" "href" (string "#" k) :content (string k)}))
  {:tag "p" :content (interpose {:tag "span" :content " " "class" "divider"} items)})
