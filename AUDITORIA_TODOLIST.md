# TodoList Detalhado - Auditoria e Padronização UNIFI MCP

**Data**: 2026-02-09
**MCP Server**: unifi-network-mcp
**MCP_ID**: `unifi`
**Total de Tools**: 84

---

## Resumo Executivo

### Não-Conformidades Identificadas

| Categoria | Total Afetadas | Severidade |
|-----------|----------------|------------|
| **Descrições em inglês** (devem ser PT-BR) | 84/84 | 🔴 CRÍTICA |
| **Descrições < 250 chars** | ~70/84 | 🔴 CRÍTICA |
| **Substantivo-chave não é primeira palavra** | ~50/84 | 🟠 ALTA |
| **Identificador UniFi < 2 menções** | ~80/84 | 🟠 ALTA |
| **Falta sinônimos de domínio** | ~84/84 | 🟠 ALTA |
| **Descrições de parâmetros em inglês** | ~100% | 🔴 CRÍTICA |
| **Nomenclatura de tools** | 0/84 | ✅ CONFORME |
| **Prefixo unifi_** | 84/84 | ✅ CONFORME |

### Conformidades Identificadas

- ✅ **Nomenclatura de tools**: Todas as 84 tools seguem padrão `unifi_{verbo}_{recurso}`
- ✅ **Prefixo obrigatório**: Todas começam com `unifi_`
- ✅ **Convenção CRUD**: Singular para item único, plural para listagem (padrão seguido)
- ✅ **Tamanho dos nomes**: Todos entre 20-48 caracteres (dentro da faixa recomendada)

---

## Plano de Correção por Categoria

### CATEGORIA 1: Descrições de Tools (84 tools)

**Impacto**: ALTO - Cada descrição deve ser reescrita em português brasileiro

**Regras a aplicar**:
1. Traduzir 100% para português brasileiro
2. Garantir 250-350 caracteres
3. Substantivo-chave como primeira palavra
4. Mencionar "UniFi" ou "Unifi Network" no mínimo 2 vezes
5. Incluir 2-4 sinônimos de domínio
6. Estrutura: [SUBSTANTIVO-CHAVE] + [QUANDO USAR] + [O QUE RETORNA]
7. Eliminar boilerplate repetitivo

**Dependências**: Nenhuma (pode ser executado primeiro)

**Estimativa**: ~84 reescritas de descrição

---

### CATEGORIA 2: Descrições de Parâmetros (estimado ~300 parâmetros)

**Impacto**: MÉDIO - Parâmetros com descrições devem ser traduzidos para PT-BR

**Regras a aplicar**:
1. Traduzir descriptions de parâmetros para português brasileiro
2. Manter casing dos nomes (não alterar `mac_address`, `client_id`, etc.)
3. Especificar formatos de data/hora quando aplicável
4. Listar valores enum quando aplicável

**Dependências**: Pode ser executado em paralelo com CATEGORIA 1

**Estimativa**: ~300 traduções de parâmetros

---

### CATEGORIA 3: Schemas de Validação (schemas.py)

**Impacto**: MÉDIO - Descrições em schemas devem ser traduzidas

**Regras a aplicar**:
1. Traduzir `description` fields em `PORT_FORWARD_SCHEMA`
2. Traduzir `description` fields em `TRAFFIC_ROUTE_SCHEMA`
3. Traduzir outros schemas encontrados

**Dependências**: Independente das outras categorias

**Estimativa**: ~50 traduções de descrições em schemas

---

## Mapeamento de Tools por Arquivo

### clients.py (10 tools)
1. `unifi_lookup_by_ip` - Descrição: 100 chars ❌
2. `unifi_list_clients` - Descrição: 107 chars ❌
3. `unifi_get_client_details` - Descrição: 67 chars ❌
4. `unifi_authorize_guest` - Descrição: 69 chars ❌
5. `unifi_unauthorize_guest` - Descrição: 56 chars ❌
6. `unifi_block_client` - Descrição: 58 chars ❌
7. `unifi_unblock_client` - Descrição: 58 chars ❌
8. `unifi_rename_client` - Descrição: 68 chars ❌
9. `unifi_force_reconnect_client` - Descrição: 66 chars ❌
10. `unifi_set_client_ip_settings` - Descrição: 171 chars ❌

### devices.py (6 tools)
11. `unifi_list_devices` - Descrição: 68 chars ❌
12. `unifi_get_device_details` - Descrição: 67 chars ❌
13. `unifi_adopt_device` - Descrição: 59 chars ❌
14. `unifi_reboot_device` - Descrição: 47 chars ❌
15. `unifi_rename_device` - Descrição: 63 chars ❌
16. `unifi_upgrade_device` - Descrição: 93 chars ❌

### events.py (4 tools)
17. `unifi_list_events` - Descrição: 154 chars ❌
18. `unifi_list_alarms` - Descrição: 157 chars ❌
19. `unifi_archive_alarm` - Descrição: 54 chars ❌
20. `unifi_archive_all_alarms` - Descrição: 47 chars ❌
21. `unifi_get_event_types` - Descrição: 142 chars ❌

### firewall.py (8 tools)
22. `unifi_list_firewall_policies` - Descrição: 73 chars ❌
23. `unifi_get_firewall_policy_details` - Descrição: 68 chars ❌
24. `unifi_create_firewall_policy` - Descrição: 59 chars ❌
25. `unifi_update_firewall_policy` - Descrição: 67 chars ❌
26. `unifi_toggle_firewall_policy` - Descrição: 54 chars ❌
27. `unifi_create_simple_firewall_policy` - Descrição: 115 chars ❌
28. `unifi_list_firewall_zones` - Descrição: 46 chars ❌
29. `unifi_list_ip_groups` - Descrição: 53 chars ❌

### hotspot.py (4 tools)
30. `unifi_create_voucher` - Descrição: 255 chars ✅ (tamanho OK, mas precisa traduzir)
31. `unifi_list_vouchers` - Descrição: 155 chars ❌
32. `unifi_get_voucher_details` - Descrição: 61 chars ❌
33. `unifi_revoke_voucher` - Descrição: 66 chars ❌

### network.py (8 tools)
34. `unifi_list_networks` - Descrição: 96 chars ❌
35. `unifi_get_network_details` - Descrição: 46 chars ❌
36. `unifi_create_network` - Descrição: 78 chars ❌
37. `unifi_update_network` - Descrição: 138 chars ❌
38. `unifi_list_wlans` - Descrição: 79 chars ❌
39. `unifi_get_wlan_details` - Descrição: 46 chars ❌
40. `unifi_create_wlan` - Descrição: 78 chars ❌
41. `unifi_update_wlan` - Descrição: 72 chars ❌

### port_forwards.py (6 tools)
42. `unifi_list_port_forwards` - Descrição: 63 chars ❌
43. `unifi_get_port_forward` - Descrição: 81 chars ❌
44. `unifi_create_port_forward` - Descrição: 102 chars ❌
45. `unifi_update_port_forward` - Descrição: 99 chars ❌
46. `unifi_toggle_port_forward` - Descrição: 74 chars ❌
47. `unifi_create_simple_port_forward` - Descrição: 82 chars ❌

### qos.py (7 tools)
48. `unifi_list_qos_rules` - Descrição: 75 chars ❌
49. `unifi_get_qos_rule_details` - Descrição: 51 chars ❌
50. `unifi_create_qos_rule` - Descrição: 73 chars ❌
51. `unifi_update_qos_rule` - Descrição: 68 chars ❌
52. `unifi_toggle_qos_rule_enabled` - Descrição: 64 chars ❌
53. `unifi_create_simple_qos_rule` - Descrição: 86 chars ❌

### routing.py (4 tools)
54. `unifi_list_routes` - Descrição: 168 chars ❌
55. `unifi_get_route_details` - Descrição: 62 chars ❌
56. `unifi_create_route` - Descrição: 153 chars ❌
57. `unifi_update_route` - Descrição: 102 chars ❌
58. `unifi_list_active_routes` - Descrição: 218 chars ❌

### stats.py (8 tools)
59. `unifi_get_alerts` - Descrição: 59 chars ❌
60. `unifi_get_client_stats` - Descrição: 54 chars ❌
61. `unifi_get_device_stats` - Descrição: 68 chars ❌
62. `unifi_get_network_stats` - Descrição: 65 chars ❌
63. `unifi_get_top_clients` - Descrição: 63 chars ❌
64. `unifi_get_dpi_stats` - Descrição: 73 chars ❌

### system.py (4 tools)
65. `unifi_get_system_info` - Descrição: 90 chars ❌
66. `unifi_get_network_health` - Descrição: 68 chars ❌
67. `unifi_get_snmp_settings` - Descrição: 75 chars ❌
68. `unifi_update_snmp_settings` - Descrição: 111 chars ❌
69. `unifi_get_site_settings` - Descrição: 87 chars ❌

### traffic_routes.py (4 tools)
70. `unifi_list_traffic_routes` - Descrição: 166 chars ❌
71. `unifi_get_traffic_route_details` - Descrição: 66 chars ❌
72. `unifi_update_traffic_route` - Descrição: 165 chars ❌
73. `unifi_toggle_traffic_route` - Descrição: 40 chars ❌

### usergroups.py (4 tools)
74. `unifi_list_usergroups` - Descrição: 153 chars ❌
75. `unifi_get_usergroup_details` - Descrição: 63 chars ❌
76. `unifi_create_usergroup` - Descrição: 179 chars ❌
77. `unifi_update_usergroup` - Descrição: 109 chars ❌

### vpn.py (4 tools)
78. `unifi_list_vpn_clients` - Descrição: 64 chars ❌
79. `unifi_get_vpn_client_details` - Descrição: 49 chars ❌
80. `unifi_update_vpn_client_state` - Descrição: 52 chars ❌
81. `unifi_list_vpn_servers` - Descrição: 67 chars ❌
82. `unifi_get_vpn_server_details` - Descrição: 49 chars ❌
83. `unifi_update_vpn_server_state` - Descrição: 52 chars ❌

### config.py (1 tool)
84. `unifi_get_site_settings` - Descrição: 87 chars ❌

---

## Domínio de Negócio: Redes e Infraestrutura

**Contexto**: UniFi Network é uma plataforma de gerenciamento de redes corporativas e residenciais.

**Sinônimos de Domínio Obrigatórios**:

| Termo Técnico | Sinônimos para Incluir |
|---------------|------------------------|
| clients | clientes, dispositivos conectados, equipamentos, aparelhos |
| devices | equipamentos de rede, aparelhos, hardware, dispositivos UniFi |
| networks | redes, VLANs, segmentos de rede, sub-redes |
| firewall policies | regras de firewall, políticas de segurança, filtros de rede |
| port forwards | redirecionamento de portas, NAT, encaminhamento |
| QoS rules | regras de qualidade, priorização de tráfego, controle de banda |
| routes | rotas estáticas, roteamento, caminhos de rede |
| traffic routes | roteamento baseado em políticas, rotas de tráfego, PBR |
| vouchers | códigos de acesso, vouchers de visitante, senhas temporárias |
| usergroups | grupos de usuário, perfis de banda, limites de velocidade |
| WLANs | redes Wi-Fi, SSIDs, redes sem fio |
| VPN clients | clientes VPN, conexões VPN, túneis VPN |
| alarms | alertas, notificações, avisos de rede |
| events | eventos de rede, logs, histórico |

---

## Ordem de Execução (Sequencial)

### Fase 1: Preparação
1. ✅ Ler diretrizes (CONCLUÍDA)
2. ✅ Ler codebase (CONCLUÍDA)
3. ✅ Criar TodoList (EM ANDAMENTO)

### Fase 2: Baseline
4. ⏳ Verificar PM2 status
5. ⏳ Executar testes existentes
6. ⏳ Testar 5+ tools representativas
7. ⏳ Salvar baseline_antes_unifi.json

### Fase 3: Implementação (Seguindo ReAct)
8. ⏳ Corrigir descrições de tools (84 tools) - CATEGORIA 1
9. ⏳ Corrigir descrições de parâmetros (~300 params) - CATEGORIA 2
10. ⏳ Corrigir schemas de validação (~50 descriptions) - CATEGORIA 3

### Fase 4: Validação
11. ⏳ Verificar PM2 status (após alterações)
12. ⏳ Executar mesmos testes
13. ⏳ Testar mesmas 5+ tools
14. ⏳ Salvar baseline_depois_unifi.json
15. ⏳ Comparar JSONs (zero regressão)

### Fase 5: Relatório
16. ⏳ Gerar relatório final consolidado

---

## Ferramentas de Teste Representativas (para baseline)

Seleção de 5 tools representando diferentes categorias:

1. **`unifi_list_clients`** - Leitura simples, uso comum
2. **`unifi_get_device_details`** - Leitura por identificador
3. **`unifi_create_voucher`** - Criação com parâmetros opcionais
4. **`unifi_toggle_firewall_policy`** - Atualização toggle
5. **`unifi_list_networks`** - Listagem de configuração

---

## Critérios de Sucesso

### Para Cada Tool:
- [ ] Descrição em português brasileiro (100%)
- [ ] Descrição entre 250-350 caracteres
- [ ] Substantivo-chave é primeira palavra
- [ ] "UniFi" ou "Unifi Network" aparece ≥ 2 vezes
- [ ] 2-4 sinônimos de domínio incluídos
- [ ] Estrutura [SUBSTANTIVO] + [QUANDO] + [RETORNO] presente
- [ ] Sem boilerplate repetitivo entre tools similares

### Para Cada Parâmetro:
- [ ] Descrição em português brasileiro
- [ ] Formato de data/hora explicitado (quando aplicável)
- [ ] Valores enum listados (quando aplicável)

### Validação Final:
- [ ] Zero regressões em testes
- [ ] Todas as tools funcionando identicamente
- [ ] PM2 rodando sem erros
- [ ] Baseline antes vs depois: funcionamento idêntico

---

## Estimativa de Impacto

| Categoria | Arquivos Afetados | Linhas Estimadas | Risco Regressão |
|-----------|-------------------|------------------|-----------------|
| Descrições de tools | 14 arquivos .py | ~84 linhas | BAIXO (apenas metadados) |
| Descrições de parâmetros | 14 arquivos .py | ~300 linhas | BAIXO (apenas docstrings) |
| Schemas | 1 arquivo (schemas.py) | ~50 linhas | BAIXO (apenas descriptions) |
| **TOTAL** | **15 arquivos** | **~434 linhas** | **BAIXO** |

**Justificativa Risco BAIXO**: Todas as alterações são APENAS em strings de metadados (descrições). Nenhuma lógica de código será alterada.

---

## Checklist de Validação Final

Após implementação, validar TODAS as regras das diretrizes:

- [ ] Todos os nomes entre 30-48 caracteres? (ou justificáveis se < 30)
- [ ] Todos os nomes iniciam com `unifi_`?
- [ ] Convenção CRUD respeitada (`{MCP_ID}_{verbo}_{recurso}`)?
- [ ] Todas as descrições entre 250-350 caracteres?
- [ ] Identificador UniFi aparece ≥ 2 vezes em cada descrição?
- [ ] Substantivo-chave é primeira palavra de cada descrição?
- [ ] Cada descrição contém 2-4 sinônimos de domínio?
- [ ] Nenhum jargão interno sem equivalente natural?
- [ ] Sem frases boilerplate repetidas?
- [ ] Estrutura [SUBSTANTIVO-CHAVE] + [QUANDO] + [RETORNO] presente?
- [ ] Parâmetros com nomes autoexplicativos?
- [ ] Casing consistente em todo o MCP?
- [ ] Descrições de parâmetros em português brasileiro?
- [ ] Formatos de data/hora explicitados?
- [ ] Parâmetros com valores fixos possuem `enum` declarado?
- [ ] Tools semelhantes diferenciadas nas descrições?
- [ ] Referências internas atualizadas?
- [ ] Zero regressões nos testes?

---

**Última Atualização**: 2026-02-09 (Análise inicial completa)
**Próximo Passo**: Estabelecer baseline (Task #4)
