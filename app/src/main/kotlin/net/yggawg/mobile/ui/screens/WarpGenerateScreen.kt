package net.yggawg.mobile.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.*
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import net.yggawg.mobile.vpn.warp.WarpAccount
import net.yggawg.mobile.config.parseAwgConf
import net.yggawg.mobile.vpn.warp.WarpApiClient

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WarpGenerateScreen(onConfigGenerated: (configText: String) -> Unit, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var isGenerating by remember { mutableStateOf(false) }
    var errorText by remember { mutableStateOf<String?>(null) }
    var account by remember { mutableStateOf<WarpAccount?>(null) }
    var showConf by remember { mutableStateOf(false) }

    errorText?.let { msg ->
        AlertDialog(
            onDismissRequest = { errorText = null },
            title = { Text("Error") },
            text = { Text(msg) },
            confirmButton = {
                TextButton(onClick = { errorText = null }) { Text("OK") }
            },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("WARP Generator") },
                navigationIcon = {
                    IconButton(onClick = onDone) {
                        Icon(Icons.Default.ArrowBack, "Back")
                    }
                },
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (account == null) {
                // Pre-generation info
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(
                            Icons.Default.Cloud,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(32.dp),
                        )
                        Text(
                            "Cloudflare WARP",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(
                            "Generate a free WireGuard VPN tunnel through " +
                            "Cloudflare's global network. " +
                            "The private key is generated on your device and " +
                            "never leaves it.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                Button(
                    onClick = {
                        isGenerating = true
                        errorText = null
                        scope.launch {
                            try {
                                val client = WarpApiClient()
                                val result = client.register()
                                account = result
                                // Cache in SharedPreferences
                                val prefs = context.getSharedPreferences(
                                    "yggawg", Context.MODE_PRIVATE
                                )
                                prefs.edit()
                                    .putString("warp_account", result.toJson().toString())
                                    .apply()

                                onConfigGenerated(result.toConfString())
                            } catch (e: WarpApiClient.WarpException) {
                                errorText = e.message
                            } catch (e: Exception) {
                                errorText = "Unexpected error: ${e.message}"
                            } finally {
                                isGenerating = false
                            }
                        }
                    },
                    enabled = !isGenerating,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (isGenerating) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("Generating…")
                    } else {
                        Icon(Icons.Default.Refresh, null)
                        Spacer(Modifier.width(8.dp))
                        Text("Generate WARP Config")
                    }
                }
            } else {
                // Post-generation results
                val acc = account!!
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Icon(
                                Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                            )
                            Text(
                                acc.nodeTag(),
                                style = MaterialTheme.typography.titleMedium,
                            )
                        }
                        InfoRow("Endpoint", acc.endpoint)
                        InfoRow("IPv4", acc.clientV4)
                        if (acc.clientV6.isNotEmpty()) {
                            InfoRow("IPv6", acc.clientV6)
                        }
                        acc.reserved?.let { InfoRow("Reserved", it) }
                    }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            val uri = acc.toWireguardUri()
                            val cm = context.getSystemService(
                                Context.CLIPBOARD_SERVICE
                            ) as ClipboardManager
                            cm.setPrimaryClip(
                                ClipData.newPlainText("WARP URI", uri)
                            )
                            Toast.makeText(
                                context, "Copied to clipboard", Toast.LENGTH_SHORT
                            ).show()
                        },
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Default.ContentCopy, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Copy URI")
                    }
                    OutlinedButton(
                        onClick = { showConf = !showConf },
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Default.Code, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("View .conf")
                    }
                }

                if (showConf) {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        val conf = remember(acc) {
                            acc.toConfString()
                        }
                        Text(
                            text = conf,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            lineHeight = 14.sp,
                            modifier = Modifier
                                .padding(8.dp)
                                .fillMaxWidth(),
                        )
                    }
                }

                OutlinedButton(
                    onClick = {
                        val uri = acc.toWireguardUri()
                        val intent = android.content.Intent(
                            android.content.Intent.ACTION_VIEW,
                            android.net.Uri.parse(uri)
                        )
                        runCatching { context.startActivity(intent) }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Default.OpenInNew, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Open in WireGuard App")
                }

                OutlinedButton(
                    onClick = { account = null },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Generate New Config")
                }
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.outline,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.widthIn(max = 200.dp),
        )
    }
}
