# BI de Ressuprimento — backend (login + filtro por empresa)

Backend Node/Express que autentica usuários e filtra os dados do BI por empresa, com base nas
tabelas `USUARIOS` / `USUARIOS_EMPRESAS` do Access, sincronizadas a partir da máquina local.

## Variáveis de ambiente (configurar no Render)

| Variável | Obrigatória | Descrição |
|---|---|---|
| `SESSION_SECRET` | sim | String aleatória longa, usada para assinar o cookie de sessão (JWT). Gere uma vez e não troque depois (trocar derruba todas as sessões ativas). |
| `SYNC_SECRET` | sim | Segredo compartilhado que o `sync_to_backend.js` (rodando no PC local) precisa enviar para poder gravar dados aqui. Mantenha em segredo. |
| `NODE_ENV` | recomendado | Definir como `production` no Render — ativa o cookie `secure` (só trafega por HTTPS). |
| `PORT` | não | O Render já define sozinho. |

## Deploy no Render

1. Suba esta pasta (`backend/`) como repositório no GitHub.
2. No Render: **New + → Web Service**, conecte o repositório.
3. Build Command: `npm install`
4. Start Command: `npm start`
5. Configure as variáveis de ambiente acima em **Environment**.
6. Depois do primeiro deploy, rode a sincronização local (veja abaixo) pelo menos uma vez — sem
   isso o servidor responde 503 em `/` (ainda sem dados) e login retorna 503 também.

## Sincronizar dados (rodar na máquina local, com acesso ao Access)

O script `../sync_to_backend.js` (uma pasta acima desta, fora do repositório) lê os `bi_*.json`
gerados pelo `extract_bi.ps1` e envia para `POST /api/sync`. Ele já é chamado automaticamente pelo
botão "🔄 Atualizar dados" do dashboard local (`local_server.js`), desde que exista um arquivo
`sync_config.json` (mesma pasta do `sync_to_backend.js`) assim:

```json
{ "url": "https://SEU-SERVICO.onrender.com/api/sync", "secret": "o-mesmo-valor-de-SYNC_SECRET" }
```

## Segurança — o que já está feito e o que fica registrado aqui

- Senha nunca é gravada em texto puro neste servidor — só o hash (bcrypt), calculado ao receber
  `/api/sync`. A senha em texto puro só existe em trânsito, sempre por HTTPS.
- Cada requisição autenticada relê, na hora, quais empresas o usuário tem vinculadas em
  `USUARIOS_EMPRESAS` (não fica "preso" ao que valia no momento do login) — desativar um usuário
  ou tirar o vínculo de uma empresa tem efeito imediato, sem precisar esperar o token expirar.
- Usuário sem nenhuma empresa vinculada não vê nada (nega por padrão).
- `/api/login` tem limite de tentativas (20 a cada 15 min por IP) contra força bruta.
- `/api/sync` só aceita gravação com o cabeçalho `X-Sync-Secret` batendo com `SYNC_SECRET`.
