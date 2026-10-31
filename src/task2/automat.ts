import { writeFile } from "node:fs/promises";

export async function getToken(
    authority: string,
    audience: string,
    clientId: string,
    clientSecret: string,
    scope: string
): Promise<string> {
    const response = await fetch(`${authority}/oauth/token`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            client_id: clientId,
            client_secret: clientSecret,
            audience: audience,
            grant_type: "client_credentials",
            scope: scope
        })
    });

    if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`);
    }

    const data = await response.json();

    if (!data.access_token) {
        throw new Error("Response data does not contain access_token");
    }

    return data.access_token;
}

export async function issuePass(
    url: string,
    token: string,
    name: string,
    document: string
): Promise<void> {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ name, document })
    });

    if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`);
    }

    const location = response.headers.get("Location");

    if (!location) {
        throw new Error("Response does not contain Location header");
    }

    const passId = new URL(location).pathname.split("/").pop();
    const image = Buffer.from(await response.arrayBuffer());

    await writeFile(`${passId}.png`, image);
}