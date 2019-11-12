/* See LICENSE in project directory */
package edu.uiowa.clc.verdict.crv;

import edu.uiowa.clc.verdict.vdm.instrumentor.VDMInstrumentor;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import verdict.vdm.vdm_data.GenericAttribute;
import verdict.vdm.vdm_model.BlockImpl;
import verdict.vdm.vdm_model.CompInstancePort;
import verdict.vdm.vdm_model.ComponentImpl;
import verdict.vdm.vdm_model.ComponentInstance;
import verdict.vdm.vdm_model.ComponentType;
import verdict.vdm.vdm_model.Connection;
import verdict.vdm.vdm_model.ConnectionEnd;
import verdict.vdm.vdm_model.Model;
import verdict.vdm.vdm_model.Port;
import verdict.vdm.vdm_model.PortMode;

// Accepts options of instrumentation and perform the operation.
// Also supports PostProcessing Kind2 Results by
// managing Mapping b/t Threats <=> Components <=> Links
// One - Component map Set of Links
// One Threat Maps List of Links
public class Instrumentor extends VDMInstrumentor {

    //
    // // Instrumentor class code:
    // private Model vdm_model;

    // ThreatID, Components/Links
    private HashMap<String, HashSet<String>> attack_cmp_link_map =
            new HashMap<String, HashSet<String>>();

    public Instrumentor(Model vdm_model) {
        super(vdm_model);
    }

    public HashMap<String, HashSet<String>> getAttackMap() {
        return this.attack_cmp_link_map;
    }

    public static Options createOptions() {

        final Options options = new Options();

        Option input_opt = new Option("i", "VDM Model", true, "Input Model File");
        Option output_opt = new Option("o", "Instrumented Model", true, "Instrumented Model File");

        Option bresult_output_opt =
                new Option("r", "Blame Assignment Output", true, "Blame Assignment Result File");

        Option kind2_output_opt = new Option("k", "Kind2 Result Output", true, "Kind2 Result File");

        options.addOption(input_opt);
        options.addOption(output_opt);

        options.addOption(bresult_output_opt);
        options.addOption(kind2_output_opt);

        //
        // "Attacks Library:\n "
        // + "1. LS = Location Spoofing \n"
        // + "2. NI = NetWork Injection \n "
        // + "3. LB = Logic Bomb \n"
        // + "4. IT = Insider Threat \n"
        // + "5. OT = Outside User Threat \n"
        // + "6. RI = Remote Code Injection \n"
        // + "7. SV = Software virus/malware/worm/trojan \n"
        // + "8. HT = Hardware Trojans \n"
        // + "9. BG = Benign (Default) \n");

        // Attack Library Options
        Option ls_opt =
                new Option(
                        "LS",
                        "Location Spoofing",
                        false,
                        "Location Spoofing attack Instrumentation");
        Option ni_opt =
                new Option("NI", "Network Injection", false, "Network Injection Instrumentation");
        Option lb_opt = new Option("LB", "Logic Bomb", false, "Logic Bomb Instrumentation");
        Option ht_opt =
                new Option("HT", "Harware Trojan", false, "Harware Trojans Instrumentation");

        Option sv_opt =
                new Option(
                        "SV",
                        "Software Virus/malware/worm/trojan",
                        false,
                        "Software Virus/malware/worm/trojan Instrumentation");

        Option ri_opt =
                new Option(
                        "RI",
                        "Remotet Code Injection",
                        false,
                        "Remotet Code Injection Instrumentation");

        Option ot_opt =
                new Option("OT", "Outsider Threat", false, "Outsider Threat Instrumentation");

        Option it_opt = new Option("IT", "Insider Threat", false, "Insider Threat Instrumentation");

        Option bn_opt = new Option("BN", "Benign", false, "Benign (Default)");

        Option bm_opt =
                new Option("B", "Blame Assignment", false, "Blame Assignment (Link Level) Default");

        Option bl_opt =
                new Option(
                        "C",
                        "Blame Assignment (Component)",
                        false,
                        "Blame Assignment (Link Level)");

        options.addOption(ls_opt);
        options.addOption(ni_opt);
        options.addOption(lb_opt);
        options.addOption(ht_opt);
        options.addOption(sv_opt);
        options.addOption(ri_opt);
        options.addOption(ot_opt);
        options.addOption(it_opt);
        options.addOption(bn_opt);
        options.addOption(bm_opt);
        options.addOption(bl_opt);

        return options;
    }

    public Model instrument(Model vdm_model, CommandLine cmdLine) {

        //        Model instrumented_model = null;

        String[] possibleThreats = {"LS", "LB", "NI", "SV", "RI", "OT", "IT", "HT", "BG"};
        List<String> threats =
                Arrays.asList(possibleThreats).stream()
                        .filter(threat -> cmdLine.hasOption(threat))
                        .collect(Collectors.toList());
        boolean blameAssignment = cmdLine.hasOption("B");
        boolean componentLevel = cmdLine.hasOption("C");

        retrieve_component_and_channels(vdm_model, threats, blameAssignment, componentLevel);

        return vdm_model;
    }

    public Model instrument(
            Model vdm_model,
            List<String> threats,
            boolean blameAssignment,
            boolean componentLevel) {
        Model instrumented_model = null;

        retrieve_component_and_channels(vdm_model, threats, blameAssignment, componentLevel);

        return instrumented_model;
    }

    public Model instrument(Model vdm_model, List<String> threats, boolean blameAssignment) {
        return instrument(vdm_model, threats, blameAssignment, false);
    }

    // Instrument Link for all outgoing edges
    @Override
    public HashSet<Connection> instrument_component(ComponentType component, BlockImpl blockImpl) {

        HashSet<Connection> vdm_links = new HashSet<Connection>();

        HashSet<String> links = new HashSet<String>();

        for (Port port : component.getPort()) {

            PortMode mode = port.getMode();

            if (mode == PortMode.OUT) {

                //                for (Connection connection : blockImpl.getConnection()) {
                //                    links.add(connection.getName());
                //                    links.add(port.getName());
                //                    links.addAll(get_ports(connection));
                //                }
                //                links.add(port.getName());
            }
            {
                // instrument_link(port, blockImpl);
                if (blockImpl != null) {
                    for (Connection connection : blockImpl.getConnection()) {
                        if (retrieve_links(connection, port)) {
                            vdm_links.add(connection);
                            links.add(connection.getName());
                            //                        links.add(get_ports(vdm_links));
                        }
                        //                    links.addAll(get_ports(connection));
                    }
                } else {

                }
            }
        }

        String attack_type = getThreatID(component.getId());

        if (this.attack_cmp_link_map.containsKey(attack_type)) {
            HashSet<String> cmp_links = this.attack_cmp_link_map.get(attack_type);
            for (Connection con : vdm_links) {
                cmp_links.addAll(get_ports(con));
            }
        }

        return vdm_links;
    }

    private String getThreatID(String componentID) {

        String attack_type = "None";

        for (String attack_id : this.attack_cmp_link_map.keySet()) {

            HashSet<String> comps = this.attack_cmp_link_map.get(attack_id);

            if (comps.contains(componentID)) {
                attack_type = attack_id;
                break;
            }
        }

        return attack_type;
    }

    // LS:
    // - Select all components in the model M such that:
    // c.Component-Group = 'GPS' v 'IMU' v 'LIDAR'
    // Generic Attribute
    // Name: Category
    // Type: String
    // Value = GPS or IRU or DME_VOR
    @Override
    public void locationSpoofing(HashSet<ComponentType> vdm_components) {

        HashSet<String> components = new HashSet<String>();

        final String GPS = "GPS";
        final String DME_VOR = "DME_VOR";
        final String IRU = "IRU";

        BlockImpl blockImpl = null;

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {

            blockImpl = componentImpl.getBlockImpl();

            // BlockImpl
            if (blockImpl != null) {

                ComponentType componentType = componentImpl.getType();

                for (ComponentInstance componentInstance : blockImpl.getSubcomponent()) {

                    componentType = componentInstance.getSpecification();
                    ComponentImpl subcomponentImpl = componentInstance.getImplementation();

                    // Option 1) Specification
                    if (componentType != null) {

                    }
                    // Option 2) Implementation
                    else if (subcomponentImpl != null) {

                        componentType = subcomponentImpl.getType();
                    }

                    List<GenericAttribute> attributeList = componentInstance.getAttribute();

                    GenericAttribute g_attribute = searchAttribute(attributeList, "Category");

                    if (g_attribute != null) {

                        String component_category = (String) g_attribute.getValue();

                        if (component_category.equalsIgnoreCase(GPS)
                                || component_category.equalsIgnoreCase(DME_VOR)
                                || component_category.equalsIgnoreCase(IRU)) {
                            vdm_components.add(componentType);
                            components.add(componentType.getId());
                        }
                    }

                    //                    String component_group = componentInstance.getCategory();
                    //                    if (component_group == null) {
                    //                        component_group = "";
                    //                    }
                    //
                    //
                    //                    if (component_group.equals("GPS")
                    //                            || component_group.equals("DME_VOR")
                    //                            || component_group.equals("IRU")) {
                    //                        vdm_components.add(componentType);
                    //                        components.add(componentType.getId());
                    //                    }

                }
            }
        }

        this.attack_cmp_link_map.put("LS", components);

        //		return components;
    }

    // NI:
    // - Select all channels ch in the model M such that:
    // ch.ConnectionType = Remote & ch.Connection-Encrypted = False &
    // ch.Connection-Authentication = False
    @Override
    public void networkInjection(HashSet<Connection> vdm_links) {

        HashSet<String> links = new HashSet<String>();

        // ArrayList<Connection> selected_channels = new ArrayList<Connection>();

        BlockImpl blockImpl = null;

        final String REMOTE_CONNECTION = "Remote";

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {
            blockImpl = componentImpl.getBlockImpl();
            // BlockImpl
            if (blockImpl != null) {

                // Selection channels (Authentication = OFF & DataEncrypted = OFF)
                for (Connection connection : blockImpl.getConnection()) {
                    // visit(connection, instrumented_channel);

                    List<GenericAttribute> attributeList = connection.getAttribute();

                    //                    ConnectionType con_type = connection.getConnType();

                    GenericAttribute attribute1 = searchAttribute(attributeList, "ConnectionType");

                    if (attribute1 != null) {
                        String con_type = (String) attribute1.getValue();

                        GenericAttribute attribute2 =
                                searchAttribute(attributeList, "isDataEncrypted");

                        if (attribute2 != null) {
                            boolean encrypted = (boolean) attribute2.getValue();

                            GenericAttribute attribute3 =
                                    searchAttribute(attributeList, "isAuthenticated");

                            if (attribute2 != null) {

                                boolean authenticated = (boolean) attribute3.getValue();

                                if (con_type == REMOTE_CONNECTION && !encrypted && !authenticated) {

                                    // selected_channels.add(connection);
                                    // LOGGER.info("(" + connection_index++ + ") " +
                                    // connection.getName());
                                    vdm_links.add(connection);
                                    links.add(connection.getName());
                                }
                            }
                        }
                    }
                }
            }
        }

        for (Connection con : vdm_links) {
            links.addAll(get_ports(con));
        }
        this.attack_cmp_link_map.put("NI", links);

        // return links;
    }

    private HashSet<String> get_ports(Connection link) {

        HashSet<String> ports = new HashSet<String>();

        //        for (Connection con : vdm_links) {

        //        ConnectionEnd con_end = link.getSource();
        //        Port src_port = con_end.getComponentPort();
        //
        //        if (src_port == null) {
        //            CompInstancePort instance_port = con_end.getSubcomponentPort();
        //            src_port = instance_port.getPort();
        //        }
        //
        //        ports.add(src_port.getName());

        ConnectionEnd con_end = link.getSource();
        Port dest_port = con_end.getComponentPort();

        if (dest_port == null) {
            CompInstancePort instance_port = con_end.getSubcomponentPort();
            dest_port = instance_port.getPort();
        }

        ports.add(dest_port.getName());

        //        }

        return ports;
    }

    // LB:
    // - Select components c in the model M such that:
    // c.ComponentType = 'Software' v c.ComponentType = 'Hybrid' & c.Manufacturer =
    // 'ThirdParty'

    // Generic Attributes

    // Name: KindOfComponent
    // Type: String
    // Value [Software] -- String Store {Software,Hybrid}

    // Name: ManufacturerType
    // Type: Enum
    // Value = {ThirdParty,InHouse}

    // Name: isAdversariallyTested
    // Type: Boolean

    @Override
    public void logicBomb(HashSet<ComponentType> vdm_components) {

        HashSet<String> components = new HashSet<String>();

        // Conditions
        //        KindOfComponent component_kind_cond_1 = KindOfComponent.SOFTWARE;
        //        KindOfComponent component_kind_cond_2 = KindOfComponent.HYBRID;
        //        ManufacturerType manufacturer_cond = ManufacturerType.THIRD_PARTY;

        final String SOFTWARE_COMPONENT = "Software";
        final String HYBRID_COMPONENT = "Hybrid";
        final String THIRDPARY_MANFUCTURE = "ThirdParty";

        BlockImpl blockImpl = null;

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {

            blockImpl = componentImpl.getBlockImpl();

            // BlockImpl
            if (blockImpl != null) {

                ComponentType componentType = componentImpl.getType();

                for (ComponentInstance componentInstance : blockImpl.getSubcomponent()) {

                    componentType = componentInstance.getSpecification();
                    ComponentImpl subcomponentImpl = componentInstance.getImplementation();

                    //                    KindOfComponent kind_of_component =
                    // componentInstance.getComponentType();
                    //                    ManufacturerType manufacturer =
                    // componentInstance.getManufacturer();

                    // Option 1) Specification
                    if (componentType != null) {

                    }
                    // Option 2) Implementation
                    else if (subcomponentImpl != null) {

                        componentType = subcomponentImpl.getType();
                    }

                    boolean adv_tested = false;

                    List<GenericAttribute> attributeList = componentInstance.getAttribute();

                    GenericAttribute attribute1 =
                            searchAttribute(attributeList, "isAdversariallyTested");

                    if (attribute1 != null) {
                        adv_tested = (boolean) attribute1.getValue();

                        GenericAttribute attribute2 =
                                searchAttribute(attributeList, "KindOfComponent");

                        if (attribute2 != null) {
                            String kind_of_component = (String) attribute2.getValue();

                            GenericAttribute attribute3 =
                                    searchAttribute(attributeList, "ManufacturerType");

                            if (attribute3 != null) {
                                String manufacturer = (String) attribute1.getValue();
                                // condition
                                //                            	if((kind_of_component ==
                                // StringEnum.Software || kind_of_component == StringEnum.Hybrid) &&
                                // manufacturer_cond == StringEnum.Hybrid && !comp_cond_3) {
                                if ((kind_of_component.equalsIgnoreCase(SOFTWARE_COMPONENT)
                                                || kind_of_component.equalsIgnoreCase(
                                                        HYBRID_COMPONENT))
                                        && manufacturer.equalsIgnoreCase(THIRDPARY_MANFUCTURE)
                                        && !adv_tested) {
                                    vdm_components.add(componentType);
                                    components.add(componentType.getId());
                                }
                            }
                        }
                    }

                    //                    if (componentInstance.isAdversariallyTested() != null) {
                    //                        comp_cond_3 =
                    // componentInstance.isAdversariallyTested();
                    //                    }
                    //
                    //                    if ((kind_of_component == component_kind_cond_1
                    //                                    || kind_of_component ==
                    // component_kind_cond_2)
                    //                            && manufacturer == manufacturer_cond
                    //                            && !comp_cond_3) {
                    //                        // Store component
                    //                        // if (!vdm_components.contains(componentType)) {
                    //                        vdm_components.add(componentType);
                    //                        components.add(componentType.getId());
                    //                        // }
                    //                    }
                }
            }
        }

        this.attack_cmp_link_map.put("LB", components);

        //		return components;
    }

    // SV:
    // - Select components c in the model M such that:
    // c.ComponentType = 'Software' v c.ComponentType = 'Hybrid' & c.Manufacturer =
    // 'ThirdParty'
    // & \exists ch\in M. p\in InputPort(c). ch = p.channel & ch.Connectin-Type =
    // Remote
    @Override
    public void softwareVirus(HashSet<ComponentType> vdm_components) {

        HashSet<String> components = new HashSet<String>();

        // Conditions
        //        KindOfComponent component_kind_cond_1 = KindOfComponent.SOFTWARE;
        //        KindOfComponent component_kind_cond_2 = KindOfComponent.HYBRID;
        //        ManufacturerType manufacturer_cond = ManufacturerType.THIRD_PARTY;

        final String SOFTWARE_COMPONENT = "Software";
        final String HYBRID_COMPONENT = "Hybrid";
        final String THIRDPARY_MANFUCTURE = "ThirdParty";
        final String REMOTE_CONNECTION = "Remote";

        BlockImpl blockImpl = null;

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {

            blockImpl = componentImpl.getBlockImpl();

            // BlockImpl
            if (blockImpl != null) {

                ComponentType componentType = componentImpl.getType();

                for (ComponentInstance componentInstance : blockImpl.getSubcomponent()) {

                    componentType = componentInstance.getSpecification();
                    ComponentImpl subcomponentImpl = componentInstance.getImplementation();

                    //                    KindOfComponent kind_of_component =
                    // componentInstance.getComponentType();
                    //                    ManufacturerType manufacturer =
                    // componentInstance.getManufacturer();

                    // Option 1) Specification
                    if (componentType != null) {

                    }
                    // Option 2) Implementation
                    else if (subcomponentImpl != null) {

                        componentType = subcomponentImpl.getType();
                    }

                    List<GenericAttribute> attributeList = componentInstance.getAttribute();
                    GenericAttribute attribute1 = searchAttribute(attributeList, "KindOfComponent");

                    if (attribute1 != null) {
                        String kind_of_component = (String) attribute1.getValue();

                        GenericAttribute attribute2 =
                                searchAttribute(attributeList, "ManufacturerType");

                        if (attribute2 != null) {
                            String manufacturer = (String) attribute1.getValue();

                            if ((kind_of_component.equalsIgnoreCase(SOFTWARE_COMPONENT)
                                            || kind_of_component.equalsIgnoreCase(HYBRID_COMPONENT))
                                    && manufacturer.equalsIgnoreCase(THIRDPARY_MANFUCTURE)) {

                                // Port
                                for (Port port : componentType.getPort()) {
                                    // System.out.print("(" + port_index + ") ");

                                    PortMode mode = port.getMode();
                                    if (mode == PortMode.IN) {
                                        // Google code style intent add error here.
                                        for (Connection con : blockImpl.getConnection()) {

                                            //				                                    ConnectionType
                                            // con_type = con.getConnType();
                                            List<GenericAttribute> attributeList1 =
                                                    con.getAttribute();

                                            GenericAttribute attribute3 =
                                                    searchAttribute(
                                                            attributeList1, "ConnectionType");

                                            if (attribute1 != null) {
                                                String con_type = (String) attribute3.getValue();

                                                if (con_type.equalsIgnoreCase(REMOTE_CONNECTION)) {

                                                    ConnectionEnd src_con = con.getSource();
                                                    Port src_port = src_con.getComponentPort();

                                                    if (src_port == null) {
                                                        CompInstancePort compPort =
                                                                src_con.getSubcomponentPort();
                                                        src_port = compPort.getPort();
                                                    }

                                                    if (port == src_port) {
                                                        vdm_components.add(componentType);
                                                        components.add(componentType.getId());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        this.attack_cmp_link_map.put("SV", components);

        //		return components;
    }

    // Remote Code Injection:
    // - Select components c in the model M such that:
    // c.ComponentType = 'Software' v c.ComponentType = 'Hybrid'
    // & \exists ch\in M. p\in InputPort(c). ch = p.channel & ch.Connectin-Type =
    // Remote
    @Override
    public void remoteCodeInjection(HashSet<ComponentType> vdm_components) {

        HashSet<String> components = new HashSet<String>();

        // Conditions
        //        KindOfComponent component_kind_cond_1 = KindOfComponent.SOFTWARE;
        //        KindOfComponent component_kind_cond_2 = KindOfComponent.HYBRID;

        final String SOFTWARE_COMPONENT = "Software";
        final String HYBRID_COMPONENT = "Hybrid";
        final String REMOTE_CONNECTION = "Remote";

        BlockImpl blockImpl = null;

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {

            blockImpl = componentImpl.getBlockImpl();

            // BlockImpl
            if (blockImpl != null) {

                ComponentType componentType = componentImpl.getType();

                for (ComponentInstance componentInstance : blockImpl.getSubcomponent()) {

                    componentType = componentInstance.getSpecification();
                    ComponentImpl subcomponentImpl = componentInstance.getImplementation();

                    //                    KindOfComponent kind_of_component =
                    // componentInstance.getComponentType();

                    // Option 1) Specification
                    if (componentType != null) {

                    }
                    // Option 2) Implementation
                    else if (subcomponentImpl != null) {

                        componentType = subcomponentImpl.getType();
                    }

                    List<GenericAttribute> attributeList = componentInstance.getAttribute();

                    GenericAttribute attribute1 = searchAttribute(attributeList, "KindOfComponent");

                    if (attribute1 != null) {
                        String kind_of_component = (String) attribute1.getValue();

                        if (kind_of_component.equalsIgnoreCase(SOFTWARE_COMPONENT)
                                || kind_of_component.equalsIgnoreCase(HYBRID_COMPONENT)) {

                            //                    if ((kind_of_component == component_kind_cond_1
                            //                            || kind_of_component ==
                            // component_kind_cond_2)) {

                            // Port
                            for (Port port : componentType.getPort()) {
                                // System.out.print("(" + port_index + ") ");

                                PortMode mode = port.getMode();
                                if (mode == PortMode.IN) {
                                    // Google code style add errror in here
                                    for (Connection con : blockImpl.getConnection()) {

                                        //	                                    ConnectionType
                                        // con_type = con.getConnType();
                                        //	                                    ConnectionType
                                        // con_type = con.getConnType();
                                        List<GenericAttribute> attributeList1 = con.getAttribute();

                                        GenericAttribute attribute3 =
                                                searchAttribute(attributeList1, "ConnectionType");

                                        if (attribute1 != null) {
                                            String con_type = (String) attribute3.getValue();

                                            if (con_type.equalsIgnoreCase(REMOTE_CONNECTION)) {

                                                //	                                    if (con_type
                                                // == ConnectionType.REMOTE) {

                                                ConnectionEnd src_con = con.getSource();
                                                Port src_port = src_con.getComponentPort();

                                                if (src_port == null) {
                                                    CompInstancePort compPort =
                                                            src_con.getSubcomponentPort();
                                                    src_port = compPort.getPort();
                                                }

                                                if (port == src_port) {
                                                    vdm_components.add(componentType);
                                                    components.add(componentType.getId());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        this.attack_cmp_link_map.put("RI", components);

        //		return components;
    }

    // HT
    // - Select all components c in the model M that meet condition:
    // ComponentKind = Hardware v Hybrid and manufacturer = ThirdParty
    @Override
    public void hardwareTrojan(HashSet<ComponentType> vdm_components) {

        HashSet<String> components = new HashSet<String>();

        //        KindOfComponent component_kind_cond_1 = KindOfComponent.HARDWARE;
        //        KindOfComponent component_kind_cond_2 = KindOfComponent.HYBRID;
        //        ManufacturerType manufacturer_cond = ManufacturerType.THIRD_PARTY;

        final String SOFTWARE_COMPONENT = "Hardware";
        final String HYBRID_COMPONENT = "Hybrid";
        final String THIRDPARY_MANFUCTURE = "ThirdParty";

        BlockImpl blockImpl = null;

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {

            blockImpl = componentImpl.getBlockImpl();

            // BlockImpl
            if (blockImpl != null) {

                ComponentType componentType = componentImpl.getType();

                for (ComponentInstance componentInstance : blockImpl.getSubcomponent()) {

                    //
                    //                    KindOfComponent kind_of_component =
                    // componentInstance.getComponentType();
                    //                    ManufacturerType manufacturer =
                    // componentInstance.getManufacturer();

                    componentType = getType(componentInstance);

                    List<GenericAttribute> attributeList = componentInstance.getAttribute();
                    GenericAttribute attribute1 = searchAttribute(attributeList, "KindOfComponent");

                    if (attribute1 != null) {
                        String kind_of_component = (String) attribute1.getValue();

                        GenericAttribute attribute2 =
                                searchAttribute(attributeList, "ManufacturerType");

                        if (attribute2 != null) {
                            String manufacturer = (String) attribute1.getValue();

                            if ((kind_of_component.equalsIgnoreCase(SOFTWARE_COMPONENT)
                                            || kind_of_component.equalsIgnoreCase(HYBRID_COMPONENT))
                                    && manufacturer.equalsIgnoreCase(THIRDPARY_MANFUCTURE)) {

                                //                    if ((kind_of_component ==
                                // component_kind_cond_1
                                //                                    || kind_of_component ==
                                // component_kind_cond_2)
                                //                            && manufacturer == manufacturer_cond)
                                // {
                                // Store component
                                vdm_components.add(componentType);
                                components.add(componentType.getId());
                                // instrument_component(componentType, blockImpl);
                            }
                        }
                    }
                }
            }
        }

        this.attack_cmp_link_map.put("HT", components);

        //		return components;
    }

    // OT
    // - Select all components c in the model M that meet condition:
    // ComponentKind = Human and c.InsideTrustedBoundary = False
    @Override
    public void outsiderThreat(HashSet<ComponentType> vdm_components) {

        HashSet<String> components = new HashSet<String>();

        //        KindOfComponent component_kind_cond_1 = KindOfComponent.HUMAN;
        final String HUMAN_COMPONENT = "Human";

        BlockImpl blockImpl = null;

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {

            blockImpl = componentImpl.getBlockImpl();

            // BlockImpl
            if (blockImpl != null) {

                ComponentType componentType = componentImpl.getType();

                for (ComponentInstance componentInstance : blockImpl.getSubcomponent()) {

                    //                    KindOfComponent kind_of_component =
                    // componentInstance.getComponentType();

                    componentType = getType(componentInstance);

                    List<GenericAttribute> attributeList = componentInstance.getAttribute();

                    GenericAttribute attribute1 = searchAttribute(attributeList, "KindOfComponent");

                    if (attribute1 != null) {
                        String kind_of_component = (String) attribute1.getValue();

                        GenericAttribute attribute2 =
                                searchAttribute(attributeList, "isInsideTrustedBoundary");

                        if (attribute2 != null) {
                            boolean trusted_boundry = (boolean) attribute1.getValue();

                            if (kind_of_component.equalsIgnoreCase(HUMAN_COMPONENT)
                                    && !trusted_boundry) {
                                // Store component
                                vdm_components.add(componentType);
                                components.add(componentType.getId());

                                // instrument_component(componentType, blockImpl);
                            }
                        }
                    }
                }
            }
        }

        this.attack_cmp_link_map.put("OT", components);
    }

    // IT
    // - Select all components c in the model M that meet condition:
    // ComponentKind = Human and c.InsideTrustedBoundary = True
    @Override
    public void insiderThreat(HashSet<ComponentType> vdm_components) {

        HashSet<String> components = new HashSet<String>();

        //        KindOfComponent component_kind_cond_1 = KindOfComponent.HUMAN;
        final String HUMAN_COMPONENT = "Human";

        BlockImpl blockImpl = null;

        for (ComponentImpl componentImpl : vdm_model.getComponentImpl()) {

            blockImpl = componentImpl.getBlockImpl();

            // BlockImpl
            if (blockImpl != null) {

                ComponentType componentType = componentImpl.getType();

                for (ComponentInstance componentInstance : blockImpl.getSubcomponent()) {

                    //                    KindOfComponent kind_of_component =
                    // componentInstance.getComponentType();

                    componentType = getType(componentInstance);
                    List<GenericAttribute> attributeList = componentInstance.getAttribute();

                    GenericAttribute attribute1 = searchAttribute(attributeList, "KindOfComponent");

                    if (attribute1 != null) {
                        String kind_of_component = (String) attribute1.getValue();

                        GenericAttribute attribute2 =
                                searchAttribute(attributeList, "isInsideTrustedBoundary");

                        if (attribute2 != null) {
                            boolean trusted_boundry = (boolean) attribute1.getValue();

                            if (kind_of_component.equalsIgnoreCase(HUMAN_COMPONENT)
                                    && trusted_boundry) {
                                // Store component
                                vdm_components.add(componentType);
                                components.add(componentType.getId());
                                // instrument_component(componentType, blockImpl);
                            }
                        }
                    }
                }
            }
        }

        this.attack_cmp_link_map.put("IT", components);
    }

    public interface MetaDataKey<T extends Serializable> extends Serializable {
        Class<T> getType();

        String getName();
    }
}
