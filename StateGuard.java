package pe.edu.esfap.portal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Autorización del estado institucional en el SERVIDOR (no se confía en el cliente):
 * cada rol solo LEE y ESCRIBE las claves que necesita; se validan los valores (sin HTML, PDF reales, tamaños)
 * y el estudiante no puede alterar estados que fijan otros roles (trámites emitidos, matrícula aprobada, importes).
 */
public final class StateGuard {
    private StateGuard() {}

    private static final ObjectMapper OM = new ObjectMapper();
    static final int MAX_STRING = 3_000_000;
    private static final Pattern PDF = Pattern.compile("data:application/pdf;base64,JVBERi[A-Za-z0-9+/=]*");
    private static final Set<String> TRAMITES = Set.of("Constancia de estudios", "Certificado de notas", "Récord académico");

    static final Map<String, Set<String>> WRITE = Map.of(
        "est", Set.of("mat", "pays", "tram", "tix"),
        "doc", Set.of("grades", "att", "mats", "libFiles", "tram", "tix"),
        "adm", Set.of("mat", "pays", "tram", "tix", "roster"),
        "ti", Set.of("backups", "tix"));

    static final Map<String, Set<String>> READ = Map.of(
        "est", Set.of("passed", "mat", "pays", "grades", "att", "tram", "tix", "lib", "libFiles", "kb"),
        "doc", Set.of("students", "grades", "att", "mats", "tram", "tix", "lib", "libFiles", "kb"),
        "adm", Set.of("mat", "pays", "tram", "tix", "roster", "lib", "libFiles", "kb"),
        "ti", Set.of("backups", "tix", "kb", "lib", "libFiles"));

    private static JsonNode basePays() {
        try {
            return OM.readTree("[{\"id\":1,\"c\":\"Matrícula 2026-II\",\"m\":120,\"st\":\"Pagado\",\"rec\":\"R-0001\",\"conc\":1},"
                + "{\"id\":2,\"c\":\"Pensión octubre\",\"m\":80,\"st\":\"Pendiente\"},{\"id\":3,\"c\":\"Pensión noviembre\",\"m\":80,\"st\":\"Pendiente\"}]");
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    /** Vista del estado que puede ver este rol. */
    public static ObjectNode readView(String role, String userId, JsonNode all) {
        ObjectNode out = OM.createObjectNode();
        if (all == null || !all.isObject()) return out;
        for (String k : READ.getOrDefault(role, Set.of())) {
            JsonNode v = all.get(k);
            if (v == null) continue;
            if ("tram".equals(k) && "est".equals(role)) {
                ArrayNode mine = OM.createArrayNode();
                if (v.isArray()) for (JsonNode t : v) if (userId.equals(t.path("est").asText(""))) mine.add(t);
                out.set(k, mine);
            } else {
                out.set(k, v);
            }
        }
        return out;
    }

    /** Aplica los cambios permitidos para el rol sobre el estado actual. Lanza IllegalArgumentException si algo es inválido. */
    public static ObjectNode mergeWrite(String role, String userId, JsonNode current, JsonNode incoming) {
        if (incoming == null || !incoming.isObject()) throw new IllegalArgumentException("estado inválido");
        ObjectNode out = (current != null && current.isObject()) ? ((ObjectNode) current).deepCopy() : OM.createObjectNode();
        out.remove("logs");
        for (String k : WRITE.getOrDefault(role, Set.of())) {
            JsonNode v = incoming.get(k);
            if (v == null) continue;
            validate(v, 0);
            if ("est".equals(role) && "tram".equals(k)) out.set(k, estTram(userId, out.get(k), v));
            else if ("est".equals(role) && "mat".equals(k)) out.set(k, estMat(out.get(k), v));
            else if ("est".equals(role) && "pays".equals(k)) out.set(k, estPays(out.get(k), v));
            else out.set(k, v);
        }
        return out;
    }

    /** El estudiante solo puede AÑADIR solicitudes propias en proceso; no puede emitir, poner códigos ni borrar. */
    private static ArrayNode estTram(String uid, JsonNode old, JsonNode inc) {
        ArrayNode merged = OM.createArrayNode();
        List<JsonNode> ownOld = new ArrayList<>();
        if (old != null && old.isArray()) {
            for (JsonNode t : old) { if (uid.equals(t.path("est").asText(""))) ownOld.add(t); else merged.add(t); }
        }
        List<JsonNode> ownInc = new ArrayList<>();
        if (inc.isArray()) for (JsonNode t : inc) if (t.isObject() && uid.equals(t.path("est").asText(""))) ownInc.add(t);
        for (int i = 0; i < ownInc.size() && i < 100; i++) {
            if (i < ownOld.size()) { merged.add(ownOld.get(i)); continue; }
            String tipo = ownInc.get(i).path("t").asText("");
            if (!TRAMITES.contains(tipo)) continue;
            ObjectNode n = OM.createObjectNode();
            n.put("t", tipo); n.put("est", uid); n.put("st", "En proceso"); n.set("datos", OM.createObjectNode());
            merged.add(n);
        }
        for (int i = ownInc.size(); i < ownOld.size(); i++) merged.add(ownOld.get(i));
        return merged;
    }

    /** La matrícula enviada la resuelve Administración; el estudiante solo puede enviarla como "Pendiente". */
    private static JsonNode estMat(JsonNode old, JsonNode inc) {
        if (old != null && old.isObject() && old.path("status").isTextual()) return old;
        if (!inc.isObject()) return old;
        ObjectNode n = OM.createObjectNode();
        ArrayNode cs = OM.createArrayNode();
        JsonNode c = inc.path("courses");
        if (c.isArray()) for (JsonNode x : c) if (x.isTextual() && x.textValue().matches("[A-Z]{3}\\d") && cs.size() < 10) cs.add(x.textValue());
        if (cs.size() > 0) n.put("status", "Pendiente"); else n.putNull("status");
        n.set("courses", cs);
        return n;
    }

    /** Importes y conceptos son fijos; el único cambio permitido es Pendiente -> Pagado con un recibo válido (pasarela simulada). */
    private static JsonNode estPays(JsonNode old, JsonNode inc) {
        JsonNode base = (old != null && old.isArray()) ? old : basePays();
        ArrayNode res = OM.createArrayNode();
        for (JsonNode p : base) {
            ObjectNode np = ((ObjectNode) p).deepCopy();
            JsonNode match = null;
            if (inc.isArray()) for (JsonNode x : inc) if (x.path("id").asInt(-1) == p.path("id").asInt(-2)) match = x;
            if (match != null && "Pendiente".equals(p.path("st").asText()) && "Pagado".equals(match.path("st").asText())
                && match.path("rec").asText("").matches("R-\\d{1,6}")) {
                np.put("st", "Pagado");
                np.put("rec", match.path("rec").asText());
            }
            res.add(np);
        }
        return res;
    }

    static void validate(JsonNode n, int depth) {
        if (depth > 12) throw new IllegalArgumentException("profundidad excedida");
        if (n.isTextual()) {
            checkString(n.textValue());
        } else if (n.isObject()) {
            Iterator<String> names = n.fieldNames();
            while (names.hasNext()) {
                String name = names.next();
                checkString(name);
                validate(n.get(name), depth + 1);
            }
        } else if (n.isArray()) {
            for (JsonNode c : n) validate(c, depth + 1);
        } else if (!(n.isNumber() || n.isBoolean() || n.isNull())) {
            throw new IllegalArgumentException("tipo no permitido");
        }
    }

    private static void checkString(String s) {
        if (s.length() > MAX_STRING) throw new IllegalArgumentException("texto demasiado largo");
        if (s.startsWith("data:")) {
            if (!PDF.matcher(s).matches()) throw new IllegalArgumentException("solo se permiten PDF válidos");
            return;
        }
        if (s.indexOf('<') >= 0 || s.indexOf('>') >= 0) throw new IllegalArgumentException("caracteres no permitidos");
    }
}
