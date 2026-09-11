# [draft — não abrir sem autorização] dom-node: descartar conexões consigo mesmo pela identidade Noise

**Repositório alvo:** `sorenplanck/dom-protocol`
**Contexto:** DOM Wallet v0.4.0 (malha P2P) — R-W3.1 da spec de implementação.

## Problema

A partir da wallet v0.4.0 o nó embutido é alcançável e seu endereço público
circula via dial-back + PEX. Nada impede esse endereço de voltar para o
próprio nó, e o core não descarta a conexão resultante.

## Evidência (revisão `38dd705`)

- `crates/dom-node/src/node.rs:506-507` — a identidade Noise própria é
  derivada (`derive_static_pubkey(&noise_privkey)`) apenas para o log
  `"Node identity: ..."`; não participa de nenhuma comparação.
- `crates/dom-wire/src/codec.rs:73-77` — `NoiseCodec::new` captura a
  identidade remota (`transport.get_remote_static()` → `peer_id`), ou seja,
  a informação necessária existe após todo handshake — mas nenhum caminho a
  compara com a chave própria.
- `git grep -n "own_pubkey\|is_self\|self_connect" 38dd705 -- crates/dom-node
  crates/dom-wire` → vazio.
- `crates/dom-node/src/pex.rs:83` (`add_peer`) e `:117`
  (`learn_inbound_peer`) — nenhum filtro de endereço próprio.

## Comportamento hoje

1. Sem hairpin NAT (maioria dos roteadores domésticos): o dial ao próprio
   endereço falha; `record_failure` (`pex.rs:205`) + backoff — vagas de
   discagem desperdiçadas em loop.
2. Com hairpin ou IP público direto: o nó completa o Noise consigo mesmo
   (nada proíbe as duas pontas de usarem a mesma chave estática), ocupando
   uma vaga de saída e uma de entrada e inflando contadores de peers.
3. O dial-back não mitiga: o endereço é genuinamente alcançável e por isso
   continua sendo propagado.

## Correção sugerida

Após o handshake (iniciador e responder), comparar
`transport.get_remote_static()` com a chave estática própria; se iguais,
fechar a conexão sem penalidade de scoring e marcar o endereço como próprio
no PEX (não rediscar, não repropagar). Custo O(1) por conexão, sem mudança
de protocolo.

## Fora do escopo da wallet

A spec v0.4.0 (§1.5/§8) proíbe corrigir isso no core dentro da release da
wallet; este draft existe para virar issue quando o mantenedor autorizar.
