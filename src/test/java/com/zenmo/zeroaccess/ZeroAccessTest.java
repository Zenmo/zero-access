package com.zenmo.zeroaccess;

import org.junit.Test;
import static org.junit.Assert.*;
import static com.zenmo.zeroaccess.ZeroAccessKt.hasRole;

/**
 * Verify functionality using a JWT of a test Keycloak environment.
 */
public class ZeroAccessTest {
    public String jwk = """
        {
            "kid": "n-X5BeXFe6pIXhDBsDu2mQ2VYc23RSZCFRU5Y6IuzC8",
            "kty": "OKP",
            "alg": "EdDSA",
            "use": "sig",
            "crv": "Ed25519",
            "x": "ILokSbk8EKH-Q1aWo_TguuDRccoSVfEbmGSbm5gcn5I"
        }
    """;

    public String expiredMagIetsToken = "eyJhbGciOiJFZERTQSIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJuLVg1QmVYRmU2cElYaERCc0R1Mm1RMlZZYzIzUlNaQ0ZSVTVZNkl1ekM4In0.eyJleHAiOjE3MTcxNTkzMTEsImlhdCI6MTcxNzE1OTAxMSwiYXV0aF90aW1lIjoxNzE3MTU5MDExLCJqdGkiOiIzMWY5NTc4ZS0xMTk2LTQ2NzMtYWExNi0yOTcxM2QxMDM4ZTAiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLnplbm1vLmNvbS9yZWFsbXMvdGVzdHJlYWxtIiwiYXVkIjoidGVzdC1jbGllbnQtcmVzb3VyY2VzIiwic3ViIjoiODc3NGJjNDQtZjkzNi00YmY4LWEyNmItOTUwOTJjNWU3OTM3IiwidHlwIjoiSUQiLCJhenAiOiJ0ZXN0LWNsaWVudC1yZXNvdXJjZXMiLCJzZXNzaW9uX3N0YXRlIjoiOWNjMjQxMDUtNzg3OC00NGViLWFlYzQtNzM4ZDNjNDhmZGMyIiwiYXRfaGFzaCI6Inp5YzNxV195UlBsNXZrdkhXSVFldFE5UnBqdF8tZDZhVUpiWi1kQkNZUkUiLCJhY3IiOiIxIiwic2lkIjoiOWNjMjQxMDUtNzg3OC00NGViLWFlYzQtNzM4ZDNjNDhmZGMyIiwicmVhbG1fcm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJNYWdJZXRzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLXRlc3RyZWFsbSJdLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImVyaWsiLCJlbWFpbCI6ImVyaWtAZXZhbnYubmwifQ.OD4Om4fU42eKuCId-bRmr2Qa38TqawvQHe57afJSuteB2uix3rqThZrE0wv41r0lqg9Dh-GF3Jcn4kU5EfQBAA";

    public String validMagIetsToken = "eyJhbGciOiJFZERTQSIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJuLVg1QmVYRmU2cElYaERCc0R1Mm1RMlZZYzIzUlNaQ0ZSVTVZNkl1ekM4In0.eyJleHAiOjIwNjI3NTg4NTIsImlhdCI6MTcxNzE1ODg1MiwiYXV0aF90aW1lIjoxNzE3MTU4ODUyLCJqdGkiOiIxOTc4OGI4Ny0xYmMzLTQ5OWYtYmNmZi0zZTY3M2NmZjMzMGYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLnplbm1vLmNvbS9yZWFsbXMvdGVzdHJlYWxtIiwiYXVkIjoidGVzdC1jbGllbnQtcmVzb3VyY2VzIiwic3ViIjoiODc3NGJjNDQtZjkzNi00YmY4LWEyNmItOTUwOTJjNWU3OTM3IiwidHlwIjoiSUQiLCJhenAiOiJ0ZXN0LWNsaWVudC1yZXNvdXJjZXMiLCJzZXNzaW9uX3N0YXRlIjoiZjUzMTM1ODgtZWVkNS00YmI3LTk5ZTMtMjRiNGRmMDgxYjUxIiwiYXRfaGFzaCI6IlVfWFppTnZuVUlvalF2dTZWbU55dG1NOEJpY1FiSDNBT1YwejJZSjhseXciLCJhY3IiOiIxIiwic2lkIjoiZjUzMTM1ODgtZWVkNS00YmI3LTk5ZTMtMjRiNGRmMDgxYjUxIiwicmVhbG1fcm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJNYWdJZXRzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLXRlc3RyZWFsbSJdLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImVyaWsiLCJlbWFpbCI6ImVyaWtAZXZhbnYubmwifQ.-ugXWjbnObfoKKd1jf_X6irJMe6QPCSJmtMhXXMnbIo9IBniV01zxVYnkHe6QCkXDJoPLExL_Ey9KeTIeO9LDQ";

    public String validMagIetsAndersToken = "eyJhbGciOiJFZERTQSIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJuLVg1QmVYRmU2cElYaERCc0R1Mm1RMlZZYzIzUlNaQ0ZSVTVZNkl1ekM4In0.eyJleHAiOjIwNjI3NTg3ODAsImlhdCI6MTcxNzE1ODc4MCwiYXV0aF90aW1lIjoxNzE3MTU4Nzc5LCJqdGkiOiJhYjNhOTIyNy1kZWNlLTRjN2UtYTRkMy1kNGYzZDVkY2U1NTEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLnplbm1vLmNvbS9yZWFsbXMvdGVzdHJlYWxtIiwiYXVkIjoidGVzdC1jbGllbnQtcmVzb3VyY2VzIiwic3ViIjoiODc3NGJjNDQtZjkzNi00YmY4LWEyNmItOTUwOTJjNWU3OTM3IiwidHlwIjoiSUQiLCJhenAiOiJ0ZXN0LWNsaWVudC1yZXNvdXJjZXMiLCJzZXNzaW9uX3N0YXRlIjoiNjIyMjU4ZjYtZjJlYy00Y2VjLWJkOGUtYzY1ZTczNjA4ODQ5IiwiYXRfaGFzaCI6Il9yODRqcW5rSG9lZkJrQmhXcUpoWGlmZnhwdUhNWTFUV0hja0hBaTVwcW8iLCJhY3IiOiIxIiwic2lkIjoiNjIyMjU4ZjYtZjJlYy00Y2VjLWJkOGUtYzY1ZTczNjA4ODQ5IiwicmVhbG1fcm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJNYWdJZXRzQW5kZXJzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLXRlc3RyZWFsbSJdLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImVyaWsiLCJlbWFpbCI6ImVyaWtAZXZhbnYubmwifQ.ZWMaHPDiZQuPrw7YzA7vbDfxeURWfRiLylGgdcx4EPVLvspmm1jyU4f4M7NpgqVow_x9JuU-Ueucht0lR6SzCw";

    @Test
    public void testHasRole() {
        assertTrue(hasRole("MagIets", validMagIetsToken, jwk));
        assertFalse(hasRole("MagIetsAnders", validMagIetsToken, jwk));

        assertThrows(
                "Access Token has expired",
                ZeroAccessException.class,
                () -> hasRole("MagIets", expiredMagIetsToken, jwk)
        );
    }
}
