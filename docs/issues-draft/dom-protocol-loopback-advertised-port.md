# [draft — não abrir sem autorização] dom-node: advertised_port e portmap com listener em loopback

**Repositório alvo:** `sorenplanck/dom-protocol`
**Contexto:** DOM Wallet v0.4.0 (malha P2P) — limitação registrada no W5 da
spec de implementação.

## Problema

Com o listener em loopback (o modo privado da wallet, e qualquer folha),
o core:

1. `advertised_port()` (`crates/dom-node/src/node.rs`) devolve a porta de
   escuta mesmo quando o bind é `127.0.0.1` — o `Hello` anuncia uma porta
   que nenhum peer externo alcança;
2. o portmap (`crates/dom-node/src/portmap.rs`) não verifica loopback e pode
   criar no roteador um mapeamento UPnP/NAT-PMP apontando para uma porta em
   que nada escuta externamente.

## Impacto

Baixo para a rede — o dial-back impede a propagação do endereço inútil —
mas o nó em modo privado polui o roteador com um mapeamento morto e anuncia
uma porta falsa no `Hello`.

## Correção sugerida

Quando o endereço de escuta é loopback: `advertised_port = 0` (não
alcançável) e portmap desligado. Sem mudança de protocolo; `Hello` com
porta 0 já significa "não alcançável" (o mesmo caminho do CGNAT).

## Fora do escopo da wallet

A spec v0.4.0 (W5/§8) manda registrar a limitação e não alterar o pin por
isso; este draft existe para virar issue quando o mantenedor autorizar.
