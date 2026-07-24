package net.yggawg.mobile.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.yggawg.mobile.warp.WarpConfig
import net.yggawg.mobile.warp.WarpEndpointPicker
import net.yggawg.mobile.warp.WarpGenerator
import net.yggawg.mobile.warp.parseWarpEndpoints

/**
 * Экран генерации Cloudflare WARP-конфига.
 *
 * Логика из LxBox:
 * 1. Читаем warp_endpoints.json для CIDR/портов
 * 2. Генерируем X25519-ключи на устройстве
 * 3. POST на api.cloudflareclient.com
 * 4. Собираем .conf для импорта
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WarpScreen(
    onConfigGenerated: (confText: String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var isLoading by remember { mutableStateOf(false) }
    var warpConfig by remember { mutableStateOf<WarpConfig?>(null) }
    var confText by remember { mutableStateOf<String?>(null) }
    var errorText by remember { mutableStateOf<String?>(null) }
    var showAdvanced by remember { mutableStateOf(false) }

    // Advanced options
    var useRandomEndpoint by remember { mutableStateOf(true) }
    var licenseKey by remember { mutableStateOf("") }

    // Error dialog
    errorText?.let { msg ->
        AlertDialog(
            onDismissRequest = { errorText = null },
            title = { Text("Error") },
            text = { Text(msg) },
            confirmButton = { TextButton(onClick = { errorText = null }) { Text("OK") } },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("WARP Generator") })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 12.dp, vertical = 8.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Info card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Default.Info, null, tint = MaterialTheme.colorScheme.primary)
                        Text("WARP", style = MaterialTheme.typography.titleSmall)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Generate a Cloudflare WARP config for secure VPN access. " +
                        "Keys are generated on-device and never leave your phone.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                }
            }

            // Generate button
            Button(
                onClick = {
                    scope.launch {
                        isLoading = true
                        errorText = null
                        warpConfig = null
                        confText = null

                        withContext(Dispatchers.IO) {
                            try {
                                // Read endpoints JSON
                                val json = context.assets.open("warp_endpoints.json")
                                    .bufferedReader().readText()
                                val endpoints = parseWarpEndpoints(json)
                                val picker = WarpEndpointPicker(endpoints)

                                // Generate WARP config
                                val generator = WarpGenerator()
                                val randomEp = if (useRandomEndpoint) {
                                    picker.randomEndpoint()
                                } else null

                                val result = generator.register(
                                    licenseKey = licenseKey.takeIf { it.isNotBlank() },
                                    endpoint = randomEp,
                                )

                                if (result.success && result.config != null) {
                                    warpConfig = result.config
                                    confText = WarpConfig.toWireGuardConf(result.config)
                                } else {
                                    errorText = result.error ?: "Unknown error"
                                }
                            } catch (e: Exception) {
                                errorText = "Error: ${e.message}"
                            }
                        }
                        isLoading = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !isLoading,
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Generating…")
                } else {
                    Icon(Icons.Default.VpnKey, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Generate WARP Config")
                }
            }

            // Advanced options
            TextButton(
                onClick = { showAdvanced = !showAdvanced },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(
                    if (showAdvanced) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    null,
                )
                Spacer(Modifier.width(4.dp))
                Text("Advanced")
            }

            if (showAdvanced) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        // Random endpoint toggle
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Random endpoint", modifier = Modifier.weight(1f))
                            Switch(
                                checked = useRandomEndpoint,
                                onCheckedChange = { useRandomEndpoint = it },
                            )
                        }
                        Text(
                            "Use a random Cloudflare IP to bypass regional blocks.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline,
                        )

                        HorizontalDivider()

                        // WARP+ license
                        OutlinedTextField(
                            value = licenseKey,
                            onValueChange = { licenseKey = it },
                            label = { Text("WARP+ License Key (optional)") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                        )
                    }
                }
            }

            // Generated config
            if (warpConfig != null && confText != null) {
                HorizontalDivider()

                Text(
                    "Generated Config",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                )

                // Config stats
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        ConfigStat("Client IPv4", warpConfig!!.clientV4)
                        ConfigStat("Client IPv6", warpConfig!!.clientV6)
                        ConfigStat("Endpoint", warpConfig!!.endpoint)
                        ConfigStat("WARP+", if (warpConfig!!.warpPlus) "Yes" else "No")
                    }
                }

                // Config preview
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 300.dp),
                ) {
                    val lines = remember(confText) { confText!!.lines() }
                    Column {
                        Text(
                            "Config preview",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        )
                        HorizontalDivider(thickness = 0.5.dp)
                        LazyColumn(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalArrangement = Arrangement.spacedBy(1.dp),
                        ) {
                            items(lines) { line ->
                                val hScroll = rememberScrollState()
                                Text(
                                    text = if (line.startsWith("PrivateKey"))
                                        "PrivateKey = [REDACTED]" else line,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    lineHeight = 15.sp,
                                    maxLines = 1,
                                    softWrap = false,
                                    modifier = Modifier.horizontalScroll(hScroll),
                                )
                            }
                        }
                    }
                }

                // Import button
                Button(
                    onClick = { confText?.let { onConfigGenerated(it) } },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                    ),
                ) {
                    Icon(Icons.Default.FileDownload, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Use This Config")
                }
            }

            // Spacer for bottom padding
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun ConfigStat(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.outline)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
